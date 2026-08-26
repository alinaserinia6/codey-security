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
