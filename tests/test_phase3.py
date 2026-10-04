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


# -- why a finding did not match -----------------------------------------
#
# Prediction.vulnerable is the run's own assertion, so it is true on every
# prediction and says nothing about the sample. Dumped into
# unmatched_predictions unqualified it read as the label, which put a clean file
# in the false-positive list looking like a bad one -- and hid the fact that an
# unmatched finding on a *vulnerable* file is charged twice.


def test_an_unmatched_prediction_carries_the_sample_label():
    gt = [GroundTruth("b", "b.c", False)]
    pred = [Prediction("b", "b.c", True, ["CWE-120"], line=4)]
    entry = evaluate("test", pred, gt).to_dict()["unmatched_predictions"][0]

    assert entry["claims_vulnerable"] is True
    assert "vulnerable" not in entry
    assert entry["sample_vulnerable"] is False
    assert entry["failure"] == "reported_on_benign_file"


def test_a_wrong_class_on_a_vulnerable_file_is_labelled_as_such():
    """The double penalty has to be visible in the list that charges it."""
    gt = [GroundTruth("v", "v.c", True, ["CWE-20"], line=4)]
    pred = [Prediction("v", "v.c", True, ["CWE-122"], line=4)]
    result = evaluate("test", pred, gt)

    entry = result.to_dict()["unmatched_predictions"][0]
    assert entry["sample_vulnerable"] is True
    assert entry["failure"] == "wrong_class_on_vulnerable_file"

    # The same file is also an unmatched ground truth, which is the other half
    # of the charge.
    assert result.metrics.confusion.fp == 1
    assert result.metrics.confusion.fn == 1
    assert [g["sample_id"] for g in result.to_dict()["unmatched_ground_truth"]] == ["v"]


def test_the_two_failure_kinds_split_the_false_positives():
    gt = [
        GroundTruth("v", "v.c", True, ["CWE-20"], line=4),
        GroundTruth("b", "b.c", False),
    ]
    pred = [
        Prediction("v", "v.c", True, ["CWE-122"], line=4),
        Prediction("b", "b.c", True, ["CWE-120"], line=4),
    ]
    result = evaluate("test", pred, gt)
    entries = result.to_dict()["unmatched_predictions"]

    assert result.metrics.confusion.fp == 2
    assert {e["failure"] for e in entries} == {
        "wrong_class_on_vulnerable_file",
        "reported_on_benign_file",
    }
    sample_level = result.metadata["sample_level"]
    assert sample_level["unmatched_findings_on_vulnerable"] == 1
    assert sample_level["benign_flagged"] == 1


def test_a_matched_prediction_is_not_annotated_as_a_failure():
    gt = [GroundTruth("v", "v.c", True, ["CWE-120"], line=4)]
    pred = [Prediction("v", "v.c", True, ["CWE-120"], line=4)]
    result = evaluate("test", pred, gt)

    assert result.to_dict()["unmatched_predictions"] == []
    assert "prediction" in result.to_dict()["matches"][0]
