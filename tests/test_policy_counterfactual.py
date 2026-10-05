"""The Wilson interval and the policy counterfactual must reproduce the table.

Two properties are pinned here.

``wilson_interval`` is checked against the exact bounds printed in table 4.8 of
the thesis.  That table existed before any code computed it, so an agreement
with it is the only proof that the shipped evaluation and the written one are
the same evaluation.

``scripts/policy_counterfactual.py`` is checked on a hand-built run where every
outcome is known in advance: one true positive, one verdict the filter throws
away, one file the candidate generator never proposed, one rejection, one
false positive and one clean file.  The point of the tool is that it attributes
a miss to the stage that lost it, so the buckets -- not just the totals -- are
what the assertions are about.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from phase3.dataset import GroundTruthDataset
from phase3.extract_predictions import (
    CONFIRMED,
    REJECTED,
    UNCERTAIN,
    predictions_from_phase2,
)
from phase3.matcher import MatchConfig
from phase3.metrics import compute_metrics, wilson_interval
from phase3.models import ConfusionMatrix

ROOT = Path(__file__).resolve().parents[1]

_spec = importlib.util.spec_from_file_location(
    "policy_counterfactual",
    ROOT / "scripts" / "policy_counterfactual.py",
)
policy = importlib.util.module_from_spec(_spec)
sys.modules["policy_counterfactual"] = policy
_spec.loader.exec_module(policy)


# Table 4.8 of the thesis: point estimate plus the Wilson 95% interval it was
# printed with.  (successes, trials, expected_low, expected_high).
THESIS_TABLE_4_8 = [
    ("precision_A", 11, 31, 0.211, 0.531),
    ("precision_C", 3, 5, 0.231, 0.882),
    ("precision_D", 5, 11, 0.213, 0.720),
    ("recall_A", 11, 300, 0.021, 0.064),
    ("recall_C", 3, 300, 0.003, 0.029),
    ("recall_D", 5, 300, 0.007, 0.038),
    ("fpr_A", 15, 300, 0.031, 0.081),
    ("fpr_C", 2, 300, 0.002, 0.024),
    ("fpr_D", 6, 300, 0.009, 0.043),
]


@pytest.mark.parametrize("name,successes,trials,low,high", THESIS_TABLE_4_8)
def test_wilson_interval_matches_thesis_table(name, successes, trials, low, high):
    interval = wilson_interval(successes, trials)
    assert round(interval[0], 3) == low, name
    assert round(interval[1], 3) == high, name


def test_wilson_interval_is_defined_at_the_extremes():
    low, high = wilson_interval(0, 300)
    assert low == 0.0 and 0.01 < high < 0.02
    low, high = wilson_interval(300, 300)
    assert low > 0.98 and high == 1.0


def test_wilson_interval_without_trials_says_nothing():
    assert wilson_interval(0, 0) == (0.0, 1.0)


def test_wilson_interval_rejects_impossible_counts():
    with pytest.raises(ValueError):
        wilson_interval(6, 5)


def test_metrics_carry_a_confidence_interval_per_rate():
    metrics = compute_metrics(ConfusionMatrix(tp=3, fp=2, fn=297, tn=298))
    assert [round(x, 3) for x in metrics.ci95["precision"]] == [0.231, 0.882]
    assert [round(x, 3) for x in metrics.ci95["recall"]] == [0.003, 0.029]
    # F1 is not a binomial proportion, so it must not pretend to have one.
    assert "f1" not in metrics.ci95
    assert metrics.to_dict()["ci95"]["precision"] == metrics.ci95["precision"]


def test_metrics_omit_intervals_for_rates_nothing_was_measured():
    metrics = compute_metrics(ConfusionMatrix())
    assert metrics.ci95 == {}


def _decision(status, *, file="sample.c", line=10, cwe=("CWE-120",),
              confidence=0.7):
    return {
        "group_id": "G-0001",
        "file": file,
        "line": line,
        "status": status,
        "confidence": confidence,
        "cwe": list(cwe),
        "rationale": "because",
    }


def test_only_confirmed_verdicts_are_reported_by_default():
    report = {"decisions": [_decision(CONFIRMED), _decision(UNCERTAIN),
                            _decision(REJECTED)]}
    assert [p.status for p in predictions_from_phase2(report, "s")] == [
        CONFIRMED
    ]


def test_a_counterfactual_policy_keeps_the_verdict_it_was_given():
    report = {"decisions": [_decision(CONFIRMED), _decision(UNCERTAIN)]}
    kept = predictions_from_phase2(report, "s",
                                   statuses=(CONFIRMED, UNCERTAIN))
    assert [p.status for p in kept] == [CONFIRMED, UNCERTAIN]


def test_an_unreadable_verdict_is_never_counted_as_a_confirmation():
    report = {"decisions": [{"status": "MAYBE", "file": "sample.c"}]}
    # The shipped policy must not report it at all...
    assert predictions_from_phase2(report, "s") == []
    # ...and a counterfactual policy that asks for it must not find a
    # confirmation hiding in it either.
    kept = predictions_from_phase2(report, "s",
                                   statuses=(CONFIRMED, UNCERTAIN))
    assert [p.status for p in kept] == [UNCERTAIN]


def test_an_unknown_policy_cannot_be_scored_by_accident():
    with pytest.raises(ValueError):
        predictions_from_phase2({"decisions": []}, "s", statuses=("MAYBE",))


def _run(tmp_path):
    """A six-file run whose every miss has exactly one cause."""
    samples = [
        {"sample_id": "v_confirmed", "file": "v_confirmed.c",
         "vulnerable": True, "cwe": ["CWE-120"], "line": 10},
        {"sample_id": "v_uncertain", "file": "v_uncertain.c",
         "vulnerable": True, "cwe": ["CWE-120"], "line": 10},
        {"sample_id": "v_rejected", "file": "v_rejected.c",
         "vulnerable": True, "cwe": ["CWE-120"], "line": 10},
        {"sample_id": "v_never_seen", "file": "v_never_seen.c",
         "vulnerable": True, "cwe": ["CWE-120"], "line": 10},
        {"sample_id": "benign_flagged", "file": "benign_flagged.c",
         "vulnerable": False, "cwe": ["CWE-120"], "line": 10},
        {"sample_id": "benign_clean", "file": "benign_clean.c",
         "vulnerable": False, "cwe": ["CWE-120"], "line": 10},
    ]
    dataset_path = tmp_path / "dataset.json"
    dataset_path.write_text(json.dumps({"samples": samples}), encoding="utf-8")

    def entry(sample_id, status=None):
        report = {
            "source": f"{sample_id}.c",
            "findings": ([] if status is None else
                         [{"file": f"{sample_id}.c", "line": 10,
                           "cwe": ["CWE-120"], "tool": "cppcheck"}]),
            "metadata": {},
        }
        phase2 = {
            "source": f"{sample_id}.c",
            "decisions": ([] if status is None else
                          [_decision(status, file=f"{sample_id}.c")]),
            "errors": [],
            "metadata": {},
        }
        return {"sample_id": sample_id, "phase1": report, "phase2": phase2}

    payload = {
        "experiment": "phase2",
        "metadata": {
            "reports": [
                entry("v_confirmed", CONFIRMED),
                entry("v_uncertain", UNCERTAIN),
                entry("v_rejected", REJECTED),
                entry("v_never_seen", None),
                entry("benign_flagged", CONFIRMED),
                entry("benign_clean", None),
            ],
            "provenance": {
                "dataset": str(dataset_path),
                "line_tolerance": 5,
                "require_cwe_match": True,
            },
        },
    }
    result_path = tmp_path / "result.json"
    result_path.write_text(json.dumps(payload), encoding="utf-8")
    return result_path, GroundTruthDataset.from_json(str(dataset_path))


def test_policy_table_and_miss_decomposition(tmp_path):
    path, dataset = _run(tmp_path)
    report = policy.analyse(path, dataset, require_cwe=None)
    rows = report["policies"]

    shipped = rows["shipped_confirmed"]
    assert shipped["confusion"] == {"tp": 1, "fp": 1, "fn": 3, "tn": 1}

    triage = rows["triage_uncertain"]
    # The uncertain verdict was a true positive and lands on no clean file, so
    # triage buys recall and precision at no cost -- the whole reason the
    # uncertain lane is worth keeping.
    assert triage["confusion"] == {"tp": 2, "fp": 1, "fn": 2, "tn": 1}
    assert triage["recall"] > shipped["recall"]
    assert triage["precision"] > shipped["precision"]

    oracle = rows["oracle_all_verdicts"]
    assert oracle["confusion"] == {"tp": 3, "fp": 1, "fn": 1, "tn": 1}

    stages = report["miss_decomposition"]["stages"]
    assert stages["matched"] == 1
    assert stages["dropped_uncertain"] == 1
    assert stages["dropped_rejected"] == 1
    assert stages["candidate_ceiling"] == 1
    assert stages["confirmed_unmatched"] == 0
    assert stages["agent_silent"] == 0
    assert stages["no_report"] == 0
    assert report["miss_decomposition"]["recoverable_by_triage"] == 1


def test_triage_queue_ranks_the_uncertain_verdicts(tmp_path):
    path, _ = _run(tmp_path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    queue = policy.triage_queue(payload)
    assert [entry["sample_id"] for entry in queue] == ["v_uncertain"]
    assert queue[0]["rank"] == 1
    assert queue[0]["confidence"] == 0.7


def test_a_run_without_reports_is_reported_not_scored(tmp_path):
    _, dataset = _run(tmp_path)
    path = tmp_path / "llm_only.json"
    path.write_text(json.dumps({"experiment": "phase2", "metadata": {}}),
                    encoding="utf-8")
    report = policy.analyse(path, dataset, require_cwe=None)
    assert "skipped" in report
    assert report["policies"] == {}


def test_match_config_follows_the_run_not_the_default():
    payload = {"metadata": {"provenance": {"line_tolerance": 9,
                                           "require_cwe_match": False}}}
    cfg = policy._match_config(payload, None)
    assert cfg == MatchConfig(line_tolerance=9,
                              require_cwe_when_available=False)
