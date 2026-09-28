"""CWE and CVE reference data for the vulnerability classes in scope.

The proposal fixes the scope: injection (command, template, code), buffer and
integer overflow in C, and unsafe deserialization plus dangerous API usage in
Python. Every class is linked to concrete, statically-detectable CVE patterns so
the final report can name a known vulnerability instead of only a CWE number.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

CATALOG_PATH = Path(__file__).resolve().parent.parent / "data" / "cve_catalog.json"


@dataclass(frozen=True)
class CveEntry:
    """A real-world vulnerability that exhibits a recognisable source-to-sink pattern."""

    cve_id: str
    project: str
    language: str
    cwe: str
    title: str
    sinks: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    reference: str = ""
    # Most CVEs have more than one weakness. ``cwe`` is the one the report is
    # filed under; the rest are recorded so a reader can see the impact that
    # follows from it, e.g. an integer overflow whose impact is an out-of-bounds
    # read.
    related_cwes: List[str] = field(default_factory=list)
    # Which authority says which weakness, kept so a mapping can be audited.
    weakness_source: str = ""
    in_scope: bool = True
    out_of_scope_reason: str = ""

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class CweEntry:
    """A weakness class, with the CVE patterns that typically realise it."""

    cwe_id: str
    name: str
    family: str
    languages: List[str] = field(default_factory=list)
    summary: str = ""
    cves: List[str] = field(default_factory=list)


def _normalize_cwe(cwe: str) -> str:
    raw = cwe.strip().upper()
    if raw.startswith("CWE-"):
        return raw
    return f"CWE-{raw}" if raw.isdigit() else raw


class VulnerabilityCatalog:
    """Lookup of weakness classes and the CVE patterns that realise them."""

    def __init__(self, cwes: Dict[str, CweEntry], cves: Dict[str, CveEntry]) -> None:
        self._cwes = cwes
        self._cves = cves

    @classmethod
    def load(cls, path: str | Path | None = None) -> "VulnerabilityCatalog":
        payload = json.loads(
            Path(path or CATALOG_PATH).read_text(encoding="utf-8")
        )
        cwes = {
            _normalize_cwe(item["cwe_id"]): CweEntry(
                cwe_id=_normalize_cwe(item["cwe_id"]),
                name=item["name"],
                family=item.get("family", "other"),
                languages=[str(x) for x in item.get("languages", [])],
                summary=item.get("summary", ""),
                cves=[str(x) for x in item.get("cves", [])],
            )
            for item in payload.get("cwes", [])
        }
        cves = {
            item["cve_id"]: CveEntry(
                cve_id=item["cve_id"],
                project=item.get("project", ""),
                language=item.get("language", ""),
                cwe=_normalize_cwe(item.get("cwe", "")),
                title=item.get("title", ""),
                sinks=[str(x) for x in item.get("sinks", [])],
                sources=[str(x) for x in item.get("sources", [])],
                reference=item.get("reference", ""),
                related_cwes=[
                    _normalize_cwe(x) for x in item.get("related_cwes", [])
                ],
                weakness_source=item.get("weakness_source", ""),
                in_scope=bool(item.get("in_scope", True)),
                out_of_scope_reason=item.get("out_of_scope_reason", ""),
            )
            for item in payload.get("cves", [])
        }
        return cls(cwes, cves)

    # -- lookups ---------------------------------------------------------
    def cwe(self, cwe_id: str) -> Optional[CweEntry]:
        return self._cwes.get(_normalize_cwe(cwe_id))

    def cve(self, cve_id: str) -> Optional[CveEntry]:
        return self._cves.get(cve_id.upper())

    def cwe_ids(self) -> List[str]:
        return sorted(self._cwes)

    def cve_ids(self) -> List[str]:
        return sorted(self._cves)

    def entry_for_cwe(self, cwe_id: str) -> Dict[str, object]:
        """Full record for a CWE, including its CVE patterns, ready for a report."""
        entry = self.cwe(cwe_id)
        if entry is None:
            return {}
        return {
            "cwe": entry.cwe_id,
            "name": entry.name,
            "family": entry.family,
            "summary": entry.summary,
            "related_cves": [self._cves[c].to_dict() for c in entry.cves if c in self._cves],
        }

    def report_fields(self, cwe_id: str) -> Dict[str, List[str]]:
        """The CVE ids and references a report entry needs for one CWE.

        The pipeline fills these from the catalogue rather than from the model,
        so a hallucinated CVE id cannot reach the report. An unknown CWE yields
        empty lists instead of raising, because a verifier is allowed to name a
        class that is not in scope.
        """
        entry = self.cwe(cwe_id)
        if entry is None:
            return {"cwe_name": "", "related_cves": [], "references": []}
        cve_ids: List[str] = []
        references: List[str] = []
        for cve_id in entry.cves:
            cve = self._cves.get(cve_id)
            if cve is None:
                continue
            cve_ids.append(cve.cve_id)
            if cve.reference and cve.reference not in references:
                references.append(cve.reference)
        # The class page is a useful reference even when no CVE is on file.
        mitre = f"https://cwe.mitre.org/data/definitions/{entry.cwe_id.split('-')[-1]}.html"
        if mitre not in references:
            references.insert(0, mitre)
        return {
            "cwe_name": entry.name,
            "related_cves": cve_ids,
            "references": references,
        }

    def suggest_cves(self, cwe_ids: List[str], *, language: str = "") -> List[CveEntry]:
        """CVE patterns that realise any of the given weakness classes.

        Used to enrich a finding with a concrete, named reference; the agent is
        never told to *find* a CVE, only which CVE patterns match the class.
        """
        seen: set[str] = set()
        result: List[CveEntry] = []
        for cwe in cwe_ids:
            entry = self.cwe(cwe)
            if entry is None:
                continue
            for cve_id in entry.cves:
                cve = self._cves.get(cve_id)
                if cve is None or cve_id in seen or not cve.in_scope:
                    continue
                if language and cve.language and cve.language != language:
                    continue
                seen.add(cve_id)
                result.append(cve)
        return result

    def validate(self) -> List[str]:
        """Problems that would let a wrong CVE reach a report.

        Run by the test suite and available as a check command, because the
        catalogue is hand-maintained reference data: a CVE that points at a CWE
        the catalogue does not define, or that is missing its reference URL, is
        a data error rather than a finding, and should not be discovered by a
        reader of the final report.
        """
        problems: List[str] = []
        for cwe_id, entry in self._cwes.items():
            if entry.cwe_id != cwe_id:
                problems.append(f"{cwe_id}: stored under the wrong key")
            for cve_id in entry.cves:
                cve = self._cves.get(cve_id)
                if cve is None:
                    problems.append(f"{cwe_id}: unknown cve {cve_id}")
                elif cve.cwe != cwe_id:
                    problems.append(
                        f"{cve_id}: back-references {cwe_id} but is filed under {cve.cwe}"
                    )
        for cve_id, cve in self._cves.items():
            if not cve.reference:
                problems.append(f"{cve_id}: no reference URL")
            if not cve.cwe:
                problems.append(f"{cve_id}: no cwe")
            if not cve.in_scope and not cve.out_of_scope_reason:
                problems.append(
                    f"{cve_id}: marked out of scope without saying why"
                )
        return problems

    def classes_for_language(self, language: str) -> List[CweEntry]:
        return [
            entry
            for entry in self._cwes.values()
            if not entry.languages or language in entry.languages
        ]


_CATALOG: Optional[VulnerabilityCatalog] = None


def get_catalog() -> VulnerabilityCatalog:
    """Process-wide cached catalog."""
    global _CATALOG
    if _CATALOG is None:
        _CATALOG = VulnerabilityCatalog.load()
    return _CATALOG
