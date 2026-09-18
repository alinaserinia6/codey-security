from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional
import hashlib
import json


@dataclass
class Finding:
    """Normalized finding emitted by any static-analysis backend."""

    tool: str
    rule_id: str
    message: str
    file: Optional[str] = None
    line: Optional[int] = None
    column: Optional[int] = None
    severity: str = "UNKNOWN"
    cwe: List[str] = field(default_factory=list)
    confidence: Optional[float] = None
    category: Optional[str] = None
    evidence: Optional[str] = None
    suggestion: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)
    fingerprint: str = ""

    def __post_init__(self) -> None:
        self.severity = self.severity.upper()
        self.cwe = sorted(set(self.cwe))
        if not self.fingerprint:
            material = "|".join(
                [
                    self.tool,
                    self.rule_id,
                    self.file or "",
                    str(self.line or ""),
                    self.message.strip(),
                ]
            )
            self.fingerprint = hashlib.sha256(material.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class NormalizedReport:
    source: str
    language: str
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "language": self.language,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "metadata": self.metadata,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


_SEVERITY_ORDER = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def deduplicate_findings(findings: List[Finding]) -> List[Finding]:
    """Deduplicate exact findings, preserving first-seen order."""
    seen = set()
    result: List[Finding] = []
    for finding in findings:
        key = finding.fingerprint or (
            finding.tool,
            finding.rule_id,
            finding.file,
            finding.line,
            finding.message,
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(finding)
    return result


def _function_at_line(
    functions: List[Dict[str, Any]], line: Optional[int]
) -> Optional[Dict[str, Any]]:
    """Return the innermost function whose line range contains `line`.

    When functions are nested (Python) the smallest enclosing function wins.
    """
    if line is None:
        return None
    best: Optional[Dict[str, Any]] = None
    best_span: Optional[int] = None
    for fn in functions:
        start = fn.get("start_line")
        end = fn.get("end_line")
        if start is None or end is None:
            continue
        if start <= line <= end:
            span = end - start
            if best_span is None or span < best_span:
                best = fn
                best_span = span
    return best


def _same_function(a: Optional[Dict[str, Any]], b: Optional[Dict[str, Any]]) -> bool:
    if a is None or b is None:
        return False
    return (
        a.get("name") == b.get("name")
        and a.get("start_line") == b.get("start_line")
        and a.get("end_line") == b.get("end_line")
    )


def correlate_findings(
    findings: List[Finding],
    functions: Optional[List[Dict[str, Any]]] = None,
    line_tolerance: int = 2,
) -> List[Dict[str, Any]]:
    """Correlate findings that likely describe the same source-level issue.

    Grouping rules (applied in order, first match wins):

    1. Same file + same function scope + shared CWE. This catches the case
       where a single vulnerability surfaces at multiple lines inside one
       function (e.g. a buffer declaration and the unsafe call site).
    2. Same file + lines within ``line_tolerance`` + (shared CWE or same rule
       family). The original conservative proximity heuristic.

    The canonical location of each group is the highest-severity member (ties
    broken by earliest line) so Phase 2 reviews the dangerous operation rather
    than an arbitrary line in the cluster.
    """
    functions = functions or []

    # Bucket by file so we never accidentally compare across files.
    by_file: Dict[str, List[Finding]] = {}
    fileless: List[Finding] = []
    for f in findings:
        if f.file:
            by_file.setdefault(f.file, []).append(f)
        else:
            fileless.append(f)

    groups: List[List[Finding]] = []

    def try_add_group(items: List[Finding]) -> None:
        for finding in items:
            finding_fn = _function_at_line(functions, finding.line)
            matched: Optional[List[Finding]] = None

            for group in groups:
                # All members of a group already share a file, but check
                # explicitly to be defensive if the caller reuses groups.
                if group[0].file != finding.file:
                    continue

                for member in group:
                    shared_cwe = bool(set(finding.cwe) & set(member.cwe))

                    # Rule 1: same function scope + shared CWE.
                    member_fn = _function_at_line(functions, member.line)
                    if shared_cwe and _same_function(finding_fn, member_fn):
                        matched = group
                        break

                    # Rule 2: near line + shared CWE or same rule family.
                    same_rule_family = (
                        finding.rule_id.split(".")[0]
                        == member.rule_id.split(".")[0]
                    )
                    near_line = (
                        finding.line is not None
                        and member.line is not None
                        and abs(finding.line - member.line) <= line_tolerance
                    )
                    if near_line and (shared_cwe or same_rule_family):
                        matched = group
                        break

                if matched is not None:
                    break

            if matched is None:
                groups.append([finding])
            else:
                matched.append(finding)

    for items in by_file.values():
        try_add_group(items)
    # Findings without a file cannot share a scope: one group each.
    for finding in fileless:
        groups.append([finding])

    correlated: List[Dict[str, Any]] = []
    for idx, group in enumerate(groups, start=1):
        canonical = max(
            group,
            key=lambda f: (
                _SEVERITY_ORDER.get(f.severity, 0),
                -(f.line if f.line is not None else 10**9),
            ),
        )
        cwes = sorted({cwe for f in group for cwe in f.cwe})
        correlated.append(
            {
                "id": f"G-{idx:04d}",
                "file": canonical.file,
                "line": canonical.line,
                "severity": canonical.severity,
                "cwe": cwes,
                "tools": sorted({f.tool for f in group}),
                "finding_fingerprints": [f.fingerprint for f in group],
                "messages": [f.message for f in group],
            }
        )
    return correlated
