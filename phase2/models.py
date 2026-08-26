from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional
import json


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
class Phase2Report:
    source: str
    language: str
    decisions: List[FinalDecision] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "language": self.language,
            "decisions": [d.to_dict() for d in self.decisions],
            "errors": self.errors,
            "metadata": self.metadata,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)
