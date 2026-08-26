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


def correlate_findings(findings: List[Finding], line_tolerance: int = 2) -> List[Dict[str, Any]]:
    """
    Correlate findings that likely describe the same source-level issue.

    This intentionally uses a conservative location/CWE key. It is not the
    final semantic correlator; the multi-agent layer can later refine these groups.
    """
    groups: List[List[Finding]] = []

    for finding in findings:
        matched = None
        for group in groups:
            representative = group[0]
            same_file = bool(finding.file and representative.file and finding.file == representative.file)
            near_line = (
                finding.line is not None
                and representative.line is not None
                and abs(finding.line - representative.line) <= line_tolerance
            )
            shared_cwe = bool(set(finding.cwe) & set(representative.cwe))
            same_rule_family = finding.rule_id.split(".")[0] == representative.rule_id.split(".")[0]

            if same_file and near_line and (shared_cwe or same_rule_family):
                matched = group
                break

        if matched is None:
            groups.append([finding])
        else:
            matched.append(finding)

    correlated: List[Dict[str, Any]] = []
    for idx, group in enumerate(groups, start=1):
        highest = max(group, key=lambda f: _SEVERITY_ORDER.get(f.severity, 0)).severity
        cwes = sorted({cwe for f in group for cwe in f.cwe})
        correlated.append(
            {
                "id": f"G-{idx:04d}",
                "file": group[0].file,
                "line": min((f.line for f in group if f.line is not None), default=None),
                "severity": highest,
                "cwe": cwes,
                "tools": sorted({f.tool for f in group}),
                "finding_fingerprints": [f.fingerprint for f in group],
                "messages": [f.message for f in group],
            }
        )
    return correlated
