from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class AgentAssessment:
    agent: str
    decision: str = "UNCERTAIN"
    confidence: float = 0.0
    rationale: str = ""
    evidence: List[str] = field(default_factory=list)
    missing_evidence: List[str] = field(default_factory=list)
    source_location: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Hypothesis:
    """A vulnerability the Scanner Agent proposed, before verification.

    The Scanner is allowed to be wrong. A hypothesis only becomes a finding
    once the Verifier Agent confirms it, so nothing here should be treated as
    evidence on its own.
    """

    cwe: str = ""
    line: Optional[int] = None
    claim: str = ""
    suspected_source: str = ""
    suspected_sink: str = ""
    id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: Dict[str, Any], index: int = 0) -> "Hypothesis":
        cwe = value.get("cwe") or ""
        if isinstance(cwe, list):
            cwe = str(cwe[0]) if cwe else ""
        try:
            line = value.get("line")
            line = int(line) if line is not None else None
        except (TypeError, ValueError):
            line = None
        return cls(
            cwe=str(cwe).strip().upper(),
            line=line,
            claim=str(value.get("claim", "")).strip(),
            suspected_source=str(value.get("suspected_source", "")).strip(),
            suspected_sink=str(value.get("suspected_sink", "")).strip(),
            id=str(value.get("id") or f"H{index + 1}"),
        )


@dataclass
class Verification:
    """The Verifier Agent's judgement on one hypothesis."""

    decision: str = "UNCERTAIN"
    confidence: float = 0.0
    cwe: List[str] = field(default_factory=list)
    severity: str = "UNKNOWN"
    explanation: str = ""
    evidence: List[str] = field(default_factory=list)
    missing_evidence: List[str] = field(default_factory=list)
    source_location: Optional[str] = None
    chain_verified: bool = False
    #: False when the reply did not contain a decision the schema knows, so a
    #: hedge the model chose can be told apart from a reply that never
    #: arrived. Only the first kind may be resolved into a verdict.
    usable: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FinalDecision:
    group_id: str
    file: Optional[str] = None
    line: Optional[int] = None
    status: str = "UNCERTAIN"
    confidence: float = 0.0
    cwe: List[str] = field(default_factory=list)
    severity: str = "UNKNOWN"
    rationale: str = ""
    evidence: List[str] = field(default_factory=list)
    agents: List[AgentAssessment] = field(default_factory=list)
    tool_support: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["agents"] = [a.to_dict() for a in self.agents]
        return payload


@dataclass
class ReportFinding:
    """One entry of the final vulnerability report.

    The proposal requires every reported vulnerability to carry a CWE, the
    related CVE where one exists, a reference, the exact location and an
    analytical explanation, so those fields are mandatory here rather than
    left for each caller to remember.
    """

    cwe: str
    severity: str = "UNKNOWN"
    file: Optional[str] = None
    line: Optional[int] = None
    function: Optional[str] = None
    explanation: str = ""
    source: str = ""
    sink: str = ""
    source_line: Optional[int] = None
    sink_line: Optional[int] = None
    chain: str = ""
    chain_verified: bool = False
    taint_origin: str = ""
    related_cves: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    confidence: float = 0.0
    detected_by: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Phase2Report:
    source: str
    language: str
    decisions: List[FinalDecision] = field(default_factory=list)
    findings: List[ReportFinding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "language": self.language,
            "decisions": [d.to_dict() for d in self.decisions],
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "metadata": self.metadata,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)
