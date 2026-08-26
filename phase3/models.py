from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

@dataclass
class GroundTruth:
    sample_id: str
    file: str
    vulnerable: bool
    cwe: List[str] = field(default_factory=list)
    line: Optional[int] = None
    function: Optional[str] = None
    finding_id: Optional[str] = None
    description: str = ""
    group_id: Optional[str] = None
    variant: Optional[str] = None
    scenario: Optional[str] = None
    language: Optional[str] = None
    def to_dict(self) -> Dict[str, Any]: return asdict(self)

@dataclass
class Prediction:
    sample_id: str
    file: str
    vulnerable: bool
    cwe: List[str] = field(default_factory=list)
    line: Optional[int] = None
    status: str = "UNKNOWN"
    confidence: float = 0.0
    source: str = "unknown"
    finding_id: Optional[str] = None
    fingerprint: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)
    def to_dict(self) -> Dict[str, Any]: return asdict(self)

@dataclass
class Match:
    prediction: Prediction
    ground_truth: GroundTruth
    score: float
    reason: str

@dataclass
class ConfusionMatrix:
    tp: int = 0; fp: int = 0; fn: int = 0; tn: int = 0
    def to_dict(self): return asdict(self)

@dataclass
class Metrics:
    confusion: ConfusionMatrix
    precision: float
    recall: float
    f1: float
    false_positive_rate: float
    specificity: float
    false_negative_rate: float
    accuracy: float
    balanced_accuracy: float
    positive_support: int
    negative_support: int
    matched_predictions: int = 0
    unmatched_predictions: int = 0
    def to_dict(self):
        d = asdict(self); d["confusion"] = self.confusion.to_dict(); return d

@dataclass
class EvaluationResult:
    experiment: str
    metrics: Metrics
    matches: List[Match] = field(default_factory=list)
    unmatched_predictions: List[Prediction] = field(default_factory=list)
    unmatched_ground_truth: List[GroundTruth] = field(default_factory=list)
    per_cwe: Dict[str, Metrics] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    def to_dict(self):
        return {
            "experiment": self.experiment,
            "metrics": self.metrics.to_dict(),
            "matches": [{"prediction": m.prediction.to_dict(), "ground_truth": m.ground_truth.to_dict(), "score": m.score, "reason": m.reason} for m in self.matches],
            "unmatched_predictions": [p.to_dict() for p in self.unmatched_predictions],
            "unmatched_ground_truth": [g.to_dict() for g in self.unmatched_ground_truth],
            "per_cwe": {k: v.to_dict() for k, v in self.per_cwe.items()},
            "metadata": self.metadata,
        }
