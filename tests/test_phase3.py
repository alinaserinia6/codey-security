from phase3.dataset import GroundTruthDataset
from phase3.evaluator import evaluate
from phase3.matcher import MatchConfig
from phase3.models import ConfusionMatrix, GroundTruth, Prediction
from phase3.metrics import compute_metrics


def test_metrics():
    m = compute_metrics(ConfusionMatrix(tp=8, fp=2, fn=2, tn=8))
    assert round(m.precision, 3) == 0.8
    assert round(m.recall, 3) == 0.8
    assert round(m.f1, 3) == 0.8
    assert round(m.false_positive_rate, 3) == 0.2


def test_matching_cwe_and_line():
    gt = GroundTruth("s1", "x.c", True, ["CWE-120"], line=10)
    pred = Prediction("s1", "/tmp/x.c", True, ["CWE-120"], line=12, source="cppcheck")
    r = evaluate("test", [pred], [gt], match_config=MatchConfig(line_tolerance=3))
    assert r.metrics.confusion.tp == 1
    assert r.metrics.confusion.fn == 0


def test_benign_sample_creates_negative_support():
    gt = [GroundTruth("v", "v.c", True, ["CWE-120"], line=4), GroundTruth("b", "b.c", False)]
    pred = [Prediction("v", "v.c", True, ["CWE-120"], line=4), Prediction("b", "b.c", True, ["CWE-120"], line=4)]
    r = evaluate("test", pred, gt)
    assert r.metrics.confusion.tp == 1
    assert r.metrics.confusion.fp == 1
    assert r.metrics.confusion.fn == 0
    assert r.metrics.confusion.tn == 0


def test_false_positives_are_counted_per_finding():
    """A benign file carrying three findings is three false positives, not one.

    FP is a finding-level quantity (README), while TN and the benign flag rate
    are sample-level.  Counting the benign side per *sample* silently dropped
    findings and made metrics.unmatched_predictions disagree with the stored
    unmatched_predictions list.
    """
    gt = [GroundTruth("v", "v.c", True, ["CWE-120"], line=4), GroundTruth("b", "b.c", False)]
    pred = [
        Prediction("v", "v.c", True, ["CWE-120"], line=4),
        Prediction("b", "b.c", True, ["CWE-120"], line=4),
        Prediction("b", "b.c", True, ["CWE-120"], line=9),
        Prediction("b", "b.c", True, ["CWE-120"], line=20),
    ]
    r = evaluate("test", pred, gt)
    assert r.metrics.confusion.fp == 3
    assert r.metrics.confusion.tn == 0
    assert r.metrics.unmatched_predictions == len(r.unmatched_predictions) == 3

    sample_level = r.metadata["sample_level"]
    assert sample_level["benign_flagged"] == 1
    assert sample_level["unmatched_findings_on_vulnerable"] == 0
    assert sample_level["findings_per_vulnerable_file"] == 1.0
