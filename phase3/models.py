"""Core data types shared by the benchmark datasets, runners and evaluator."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class GroundTruth:
    """One labelled sample: a file, whether it is vulnerable, and its CWE."""

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

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Prediction:
    """One reported vulnerability, as produced by a tool or an agent pipeline."""

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

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Match:
    """A prediction paired with the ground truth it was credited against."""

    prediction: Prediction
    ground_truth: GroundTruth
    score: float
    reason: str


@dataclass
class ConfusionMatrix:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    def to_dict(self) -> Dict[str, int]:
        return asdict(self)


@dataclass
class Metrics:
    """Finding-level precision/recall/F1 plus sample-level benign-side rates.

    ``precision``/``recall``/``f1`` are computed over *findings*: a true positive
    is a prediction matched to a ground truth, and ``confusion`` holds those
    three counts -- except ``confusion.tn``, which is the number of benign
    files nothing was reported on, because a file is the unit that can be
    clean.

    The benign-side rates (``false_positive_rate``, ``specificity``,
    ``accuracy``, ``balanced_accuracy``) are counts of *files* and come from
    ``sample_confusion``, never from ``confusion``. ``negative_support`` is the
    number of benign files and is therefore the same for every leg run on the
    same dataset, which is what makes those rates comparable between legs. See
    :mod:`phase3.metrics`.
    """

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
    #: The same run counted in files: TP = vulnerable files with a matched
    #: finding, FP = benign files flagged, FN = vulnerable files missed,
    #: TN = benign files left clean. Every cell is a sample, so these four
    #: rates are comparable between legs in a way the mixed matrix is not.
    sample_confusion: ConfusionMatrix = field(
        default_factory=ConfusionMatrix
    )
    matched_predictions: int = 0
    unmatched_predictions: int = 0

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["confusion"] = self.confusion.to_dict()
        return payload


@dataclass
class EvaluationResult:
    experiment: str
    metrics: Metrics
    matches: List[Match] = field(default_factory=list)
    unmatched_predictions: List[Prediction] = field(default_factory=list)
    unmatched_ground_truth: List[GroundTruth] = field(default_factory=list)
    per_cwe: Dict[str, Metrics] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "experiment": self.experiment,
            "metrics": self.metrics.to_dict(),
            "matches": [
                {
                    "prediction": match.prediction.to_dict(),
                    "ground_truth": match.ground_truth.to_dict(),
                    "score": match.score,
                    "reason": match.reason,
                }
                for match in self.matches
            ],
            "unmatched_predictions": [p.to_dict() for p in self.unmatched_predictions],
            "unmatched_ground_truth": [g.to_dict() for g in self.unmatched_ground_truth],
            "per_cwe": {cwe: metrics.to_dict() for cwe, metrics in self.per_cwe.items()},
            "metadata": self.metadata,
        }
