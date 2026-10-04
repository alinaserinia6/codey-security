import importlib.util
import sys
from pathlib import Path

import pytest

from phase3.evaluator import evaluate
from phase3.matcher import MatchConfig
from phase3.models import ConfusionMatrix, GroundTruth, Prediction
from phase3.metrics import compute_metrics

ROOT = Path(__file__).resolve().parents[1]


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


def test_per_cwe_carries_the_match_counts_of_its_own_findings():
    """A per-CWE row reports how many findings it credited and how many it charged.

    ``confusion`` alone does not say how many findings were involved, so
    ``matched_predictions``/``unmatched_predictions`` are reported alongside
    it -- the same two counters the aggregate row carries.  Dropping them made
    the frozen result files disagree with each other about whether a per-CWE
    block has them at all.
    """
    gt = [
        GroundTruth("v122", "v122.c", True, ["CWE-122"], line=4),
        GroundTruth("b122", "b122.c", False, ["CWE-122"], line=4),
        GroundTruth("v190", "v190.c", True, ["CWE-190"], line=4),
    ]
    pred = [
        Prediction("v122", "v122.c", True, ["CWE-122"], line=4),
        Prediction("b122", "b122.c", True, ["CWE-122"], line=4),
        Prediction("v190", "v190.c", True, ["CWE-190"], line=4),
    ]
    per_cwe = evaluate("test", pred, gt).per_cwe

    cwe122 = per_cwe["CWE-122"]
    assert cwe122.matched_predictions == 1
    assert cwe122.unmatched_predictions == 1  # the finding on the clean file
    assert cwe122.sample_confusion.tp == 1 and cwe122.sample_confusion.fp == 1

    cwe190 = per_cwe["CWE-190"]
    assert cwe190.matched_predictions == 1
    assert cwe190.unmatched_predictions == 0


def _recompute_module():
    spec = importlib.util.spec_from_file_location(
        "recompute_result", ROOT / "scripts" / "recompute_result.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["recompute_result"] = module
    spec.loader.exec_module(module)
    return module


def test_stored_findings_read_back_into_predictions():
    """A run that stores no reports is re-scored from the finding set it has.

    The LLM-only leg keeps only its verdicts, so refreshing its metrics means
    reading every prediction back out of ``matches`` + ``unmatched_predictions``
    and re-running the matcher.  Unmatched entries come in two shapes -- the
    run's assertion was later renamed ``vulnerable`` ->
    ``claims_vulnerable`` -- and both must read back to the same
    ``Prediction``.
    """
    module = _recompute_module()

    matched = Prediction("v", "v.c", True, ["CWE-120"], line=4).to_dict()
    current = Prediction("b1", "b1.c", True, ["CWE-120"], line=4).to_dict()
    current["claims_vulnerable"] = current.pop("vulnerable")
    current["sample_vulnerable"] = False
    current["failure"] = "reported_on_benign_file"
    legacy = Prediction("b2", "b2.c", True, ["CWE-120"], line=4).to_dict()

    payload = {
        "matches": [{"prediction": matched}],
        "unmatched_predictions": [current, legacy],
        "metadata": {"positive_prediction_count": 3},
    }
    rebuilt = module._predictions_from_result(payload)

    # Returned in a canonical order: greedy_match breaks score ties by
    # prediction index, so rebuilding from matches + unmatched_predictions
    # would otherwise shuffle the stored matches on every pass.
    assert [(p.sample_id, p.vulnerable, p.line) for p in rebuilt] == [
        ("b1", True, 4),
        ("b2", True, 4),
        ("v", True, 4),
    ]


def test_partial_finding_set_is_refused():
    """Re-scoring a truncated finding set would yield a plausible wrong table."""
    module = _recompute_module()
    matched = Prediction("v", "v.c", True, ["CWE-120"], line=4).to_dict()
    payload = {
        "matches": [{"prediction": matched}],
        "unmatched_predictions": [],
        "metadata": {"positive_prediction_count": 3},
    }

    with pytest.raises(ValueError, match="incomplete"):
        module._predictions_from_result(payload)
