"""The paired test must disagree with the marginal intervals.

Table 4.8 of the thesis reports one Wilson interval per run and concludes that
C and D cannot be separated while the false-positive reduction can.  Those are
claims about *pairs* of runs, so they belong to McNemar's test; this module is
checked against both properties:

* the exact test reproduces hand-computed binomial tails, including the
  ``2·2⁻ⁿ`` values that the shipped A-vs-C comparison turns out to produce;
* on a synthetic corpus with a known disagreement pattern, each stratum
  reports the discordance the pattern was built from.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

from phase3.models import GroundTruth
from phase3.significance import (
    chi_square_mcnemar,
    discordance,
    exact_mcnemar,
    paired_comparison,
    sample_outcomes,
)

ROOT = Path(__file__).resolve().parents[1]

_spec = importlib.util.spec_from_file_location(
    "compare_paired",
    ROOT / "scripts" / "compare_paired.py",
)
compare_paired = importlib.util.module_from_spec(_spec)
sys.modules["compare_paired"] = compare_paired
_spec.loader.exec_module(compare_paired)


def test_no_disagreement_is_no_evidence():
    assert exact_mcnemar(0, 0) == 1.0
    assert chi_square_mcnemar(0, 0) == 1.0


def test_a_clean_sweep_is_two_times_the_single_tail():
    # Eight files found only by A: 2 * P(X <= 0) under a fair coin, n = 8.
    assert exact_mcnemar(8, 0) == pytest.approx(2 / 256)
    # The A-vs-C recall comparison on the 600-sample subset is exactly this
    # shape: eight positives found by A alone and none by C.
    assert round(exact_mcnemar(8, 0), 4) == 0.0078
    assert round(exact_mcnemar(13, 0), 6) == 0.000244


def test_the_exact_test_is_symmetric():
    assert exact_mcnemar(3, 9) == exact_mcnemar(9, 3)


def test_the_exact_test_never_exceeds_one():
    assert exact_mcnemar(0, 400) <= 1.0


def test_a_large_discordance_falls_back_to_the_chi_square_limit():
    # Past EXACT_LIMIT the binomial tail cannot be summed in float precision.
    assert 0.0 <= exact_mcnemar(700, 600) <= 1.0


def test_impossible_counts_are_rejected():
    with pytest.raises(ValueError):
        exact_mcnemar(-1, 3)


def test_the_chi_square_form_is_more_agreeable_than_exact_when_tied():
    # A 1-vs-1 disagreement: the exact test refuses to call it significant.
    assert exact_mcnemar(1, 1) == 1.0
    assert chi_square_mcnemar(1, 1) == pytest.approx(1.0)
    # A lopsided one is significant under the exact test and near it under
    # the approximation, in the same direction.
    assert exact_mcnemar(30, 5) < 0.001
    assert chi_square_mcnemar(30, 5) < 0.001


def test_discordance_refuses_to_pair_different_populations():
    with pytest.raises(ValueError):
        discordance({"a": True, "b": False}, {"a": True})


def _ground_truth():
    return [
        GroundTruth(f"p{i}", f"p{i}.c", True, ["CWE-120"], line=1)
        for i in range(1, 9)
    ] + [
        GroundTruth(f"n{i}", f"n{i}.c", False, ["CWE-120"], line=1)
        for i in range(1, 9)
    ]


def _payload(detected, flagged):
    return {
        "matches": [
            {"prediction": {"sample_id": sample_id}} for sample_id in detected
        ],
        "unmatched_predictions": [
            {"sample_id": sample_id, "sample_vulnerable": False,
             "claims_vulnerable": True}
            for sample_id in flagged
        ],
    }


def test_outcomes_are_read_from_the_stored_findings_not_the_metrics():
    payload = _payload(detected=["p1", "p2"], flagged=["n1"])
    outcomes = sample_outcomes(payload, _ground_truth())
    assert outcomes["positive_detection"] == {
        f"p{i}": (i <= 2) for i in range(1, 9)
    }
    assert outcomes["benign_flagging"] == {f"n{i}": (i == 1)
                                           for i in range(1, 9)}
    # A clean file counted as correct means NOT flagged; a vulnerable one
    # means detected. The two populations are scored in opposite directions.
    assert outcomes["accuracy"]["p1"] is True
    assert outcomes["accuracy"]["p3"] is False
    assert outcomes["accuracy"]["n1"] is False
    assert outcomes["accuracy"]["n2"] is True


def test_a_prediction_outside_the_ground_truth_is_an_error_not_a_miss():
    payload = _payload(detected=[], flagged=["n1", "ghost"])
    with pytest.raises(ValueError, match="absent from the ground truth"):
        sample_outcomes(payload, _ground_truth())


def test_paired_comparison_reports_each_stratum_separately():
    # A finds p1-p4 and flags n1,n2; B finds p3-p8 and flags only n1.
    a = _payload(detected=[f"p{i}" for i in range(1, 5)],
                 flagged=["n1", "n2"])
    b = _payload(detected=[f"p{i}" for i in range(3, 9)], flagged=["n1"])
    comparison = paired_comparison(a, b, _ground_truth())

    recall = comparison["strata"]["positive_detection"]
    assert (recall["b_a_only"], recall["c_b_only"]) == (2, 4)
    assert recall["rate_a"] == 0.5 and recall["rate_b"] == 0.75
    assert recall["p_value"] == pytest.approx(exact_mcnemar(2, 4), abs=1e-9)
    assert recall["p_value"] == pytest.approx(0.6875, abs=1e-9)

    benign = comparison["strata"]["benign_flagging"]
    assert (benign["b_a_only"], benign["c_b_only"]) == (1, 0)
    assert benign["rate_a"] == 0.25 and benign["rate_b"] == 0.125

    accuracy = comparison["strata"]["accuracy"]
    assert (accuracy["b_a_only"], accuracy["c_b_only"]) == (2, 5)
    assert accuracy["n"] == 16
    assert accuracy["p_value"] == pytest.approx(exact_mcnemar(2, 5), abs=1e-9)

    assert comparison["identical"] is False
    # Both tests are always available so the choice of method is visible.
    assert "p_value_exact" in recall and "p_value_chi2" in recall


def test_identical_runs_are_flagged_as_such():
    payload = _payload(detected=["p1"], flagged=[])
    comparison = paired_comparison(payload, payload, _ground_truth())
    assert comparison["identical"] is True
    assert all(row["b_a_only"] == 0 and row["c_b_only"] == 0
               for row in comparison["strata"].values())


def test_the_method_must_be_named():
    with pytest.raises(ValueError):
        paired_comparison({}, {}, _ground_truth(), method="t-test")


def test_a_one_sided_p_value_is_never_serialised_as_zero():
    # 41 vulnerable files, found by A and missed by B: the exact p is
    # 2 * 2 ** -40, which rounding to ten decimal places reports as 0.0.
    # "p = 0" is a claim of certainty the test does not make.
    gt = [
        GroundTruth(f"p{i}", f"p{i}.c", True, ["CWE-120"], line=1)
        for i in range(41)
    ] + [GroundTruth("n1", "n1.c", False, ["CWE-120"], line=1)]
    a = _payload(detected=[f"p{i}" for i in range(41)], flagged=[])
    b = _payload(detected=[], flagged=[])
    recall = paired_comparison(a, b, gt)["strata"]["positive_detection"]
    assert recall["b_a_only"] == 41
    assert recall["c_b_only"] == 0
    assert recall["p_value"] == pytest.approx(exact_mcnemar(41, 0))
    assert recall["p_value"] > 0.0
    assert compare_paired._p(recall["p_value"]) == "9.1e-13"
    # Rates are untouched by that rule: they keep six decimal places, so a
    # recall reconstructed from the counts still matches the printed one.
    assert recall["rate_a"] == 1.0


def test_comparison_formatter_renders_a_small_p_value():
    assert compare_paired._p(2.1e-09) == "2.1e-09"
    assert compare_paired._p(0.0078) == "0.0078"
    assert compare_paired._p(1.0) == "1.0000"
