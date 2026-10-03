"""The offline replay harness has to be the pipeline, minus the transport.

``scripts/replay_thinking.py`` exists to answer "did this change move the
numbers, or did it only move code". That answer is worthless if the harness is
not a faithful copy of the decisions the live run made, and it drifted
silently: it kept the *first* verifier answer where the pipeline keeps the last,
it reimplemented the fallback condition instead of calling it, and it skipped the
hedge resolution step. On a recorded run that reported 17 false positives where
the live run had 3.

These tests pin the divergences that actually happened, plus the property that
matters most -- that the harness reproduces a run it is given.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any, Dict

import pytest

from analyzers.catalog import get_catalog
from analyzers.structural_analyzer import StructuralAnalyzer
from phase2.multiagent import MultiAgentConfig, MultiAgentPipeline

_spec = importlib.util.spec_from_file_location(
    "replay_thinking",
    Path(__file__).resolve().parents[1] / "scripts" / "replay_thinking.py",
)
replay_thinking = importlib.util.module_from_spec(_spec)
sys.modules["replay_thinking"] = replay_thinking
_spec.loader.exec_module(replay_thinking)


VULNERABLE = '''
import subprocess

def run_user_command(command):
    subprocess.call(command, shell=True)
'''

CONFIRMED = {
    "decision": "CONFIRMED",
    "confidence": 0.9,
    "cwe": ["CWE-78"],
    "chain_verified": True,
    "explanation": "argv reaches the shell",
}

CONTRADICTORY = {
    **CONFIRMED,
    "missing_evidence": ["no recovered chain reaches this sink"],
}


def pipeline(**cfg) -> MultiAgentPipeline:
    pipe = MultiAgentPipeline.__new__(MultiAgentPipeline)
    pipe.cfg = MultiAgentConfig(**cfg)
    pipe.catalog = get_catalog()
    return pipe


def phase1_report(path: Path, findings=None) -> Dict[str, Any]:
    structure = StructuralAnalyzer().analyze_file(path)
    return {
        "source": str(path),
        "language": structure["language"],
        "findings": findings or [],
        "metadata": {"structure": structure},
    }


def scanner_call(hypotheses: list) -> Dict[str, Any]:
    return {"role": "scanner", "answer": {"hypotheses": hypotheses}, "error": None}


def verifier_call(hypothesis: str, answer: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "role": "verifier",
        "hypothesis": hypothesis,
        "answer": answer,
        "error": None,
    }


def entry(*calls: Dict[str, Any]) -> Dict[str, Any]:
    return {"file": "x.c", "calls": list(calls)}


HYPOTHESIS = {"cwe": "CWE-78", "line": 6, "claim": "argv into shell"}


# -- the recorded verdict is the one that was judged ----------------------

def test_the_last_verifier_answer_is_the_one_replayed():
    """The Contradiction nudge means a hypothesis can be answered twice.

    The pipeline judges the second answer. Keeping the first scores an answer
    the run threw away, which on a recorded run was 18 of the hypotheses and the
    entire difference between 3 and 17 false positives.
    """
    log = entry(
        scanner_call([HYPOTHESIS]),
        verifier_call("H1", CONTRADICTORY),
        verifier_call("H1", CONFIRMED),
    )
    verdicts = replay_thinking._final_verdicts(log)

    assert list(verdicts) == ["H1"]
    assert verdicts["H1"].missing_evidence == []


def test_a_single_answer_is_unaffected():
    log = entry(scanner_call([HYPOTHESIS]), verifier_call("H1", CONFIRMED))
    assert replay_thinking._final_verdicts(log)["H1"].decision == "CONFIRMED"


def test_an_errored_call_is_not_a_verdict():
    """A failed transport produced no answer, so it cannot be replayed as one."""
    log = entry(
        scanner_call([HYPOTHESIS]),
        {"role": "verifier", "hypothesis": "H1", "answer": None, "error": "timeout"},
    )
    assert replay_thinking._final_verdicts(log) == {}
    assert replay_thinking._errored_calls(log, "verifier") == 1


def test_a_hedge_is_resolved_before_it_is_gated():
    """The pipeline resolves UNCERTAIN before the gates see the verdict.

    Skipping that step scores a hedge as a hedge, so a run that lost a finding
    to hedge resolution replays as one that kept it.
    """
    hedge = {
        "decision": "UNCERTAIN",
        "confidence": 0.9,
        "cwe": ["CWE-78"],
        "chain_verified": True,
        "explanation": "probably reachable",
    }
    log = entry(scanner_call([HYPOTHESIS]), verifier_call("H1", hedge))
    result = replay_thinking.replay_file(
        pipeline(), phase1_report(_write(VULNERABLE)), log
    )

    assert [d["status"] for d in result["decisions"]] == ["CONFIRMED"]
    assert "hedge resolved" in result["decisions"][0]["rationale"]


# -- the fallback predicate is the pipeline's, not a copy -----------------

def test_the_declined_scanner_fallback_is_replayed():
    """The case that was silently losing recall has to replay too.

    A Scanner that answers with an empty list while Phase 1 has findings hands
    the tool findings to the verifier. The harness used to reimplement the
    condition and so missed this path entirely.
    """
    report = phase1_report(
        _write(VULNERABLE),
        findings=[{"cwe": "CWE-327", "line": 3, "message": "weak hash"}],
    )
    log = entry(scanner_call([]), verifier_call("T1", {**CONFIRMED, "cwe": ["CWE-327"]}))
    result = replay_thinking.replay_file(pipeline(), report, log)

    assert result["metadata"]["scanner_fallback"] is True
    assert (
        result["metadata"]["scanner_fallback_reason"]
        == "scanner_declined_but_tools_flagged_the_file"
    )
    assert len(result["findings"]) == 1


def test_a_failed_scanner_fallback_is_replayed():
    report = phase1_report(
        _write(VULNERABLE),
        findings=[{"cwe": "CWE-327", "line": 3, "message": "weak hash"}],
    )
    log = entry(
        {"role": "scanner", "answer": None, "error": "connection reset"},
        verifier_call("T1", {**CONFIRMED, "cwe": ["CWE-327"]}),
    )
    result = replay_thinking.replay_file(pipeline(), report, log)

    assert result["metadata"]["scanner_fallback_reason"] == "scanner_failed"


def test_silence_stays_silent_when_there_is_nothing_to_fall_back_to():
    report = phase1_report(_write(VULNERABLE))
    result = replay_thinking.replay_file(pipeline(), report, entry(scanner_call([])))

    assert "scanner_fallback" not in result["metadata"]
    assert result["findings"] == []


@pytest.mark.parametrize(
    "empty,failed,proposed,tool_findings,expected",
    [
        (False, False, 0, [], ""),
        (False, True, 0, [{}], ""),
        (True, True, 0, [{}], "scanner_failed"),
        (True, False, 2, [{}], "all_hypotheses_dropped_as_echoes"),
        (True, False, 0, [{}], "scanner_declined_but_tools_flagged_the_file"),
        (True, False, 0, [], ""),
    ],
)
def test_the_fallback_predicate(
    empty, failed, proposed, tool_findings, expected
):
    """The three ways to fall back, and the one case that means silence."""
    assert (
        MultiAgentPipeline._fallback_reason(empty, failed, proposed, tool_findings)
        == expected
    )


def test_the_harness_delegates_the_fallback_to_the_pipeline(monkeypatch):
    """If the two can disagree, the harness measures a program that never ran."""
    called = []
    monkeypatch.setattr(
        MultiAgentPipeline,
        "_fallback_reason",
        staticmethod(lambda *a: called.append(a) or ""),
    )
    replay_thinking.replay_file(
        pipeline(), phase1_report(_write(VULNERABLE)), entry(scanner_call([]))
    )
    assert called, "the harness must not decide the fallback for itself"


# -- the property that matters -------------------------------------------

def test_a_contradiction_retry_survives_a_round_trip(tmp_path):
    """End to end: what the pipeline would have judged, the harness judges.

    This is the case the drift broke. The live run asked again, took the second
    answer, and reported one finding. A harness keeping the first answer either
    drops it on the contradiction or reports it with the wrong class.
    """
    report = phase1_report(_write(VULNERABLE))
    log = entry(
        scanner_call([HYPOTHESIS]),
        verifier_call("H1", CONTRADICTORY),
        verifier_call("H1", CONFIRMED),
    )
    result = replay_thinking.replay_file(pipeline(), report, log)

    assert len(result["findings"]) == 1
    assert result["findings"][0]["cwe"] == "CWE-78"
    assert [d["status"] for d in result["decisions"]] == ["CONFIRMED"]


def test_merges_are_replayed(tmp_path):
    """The merge is part of the deterministic half, so it has to be here."""
    report = phase1_report(_write(VULNERABLE))
    log = entry(
        scanner_call(
            [
                {"cwe": "CWE-476", "line": 6, "claim": "a"},
                {"cwe": "CWE-787", "line": 6, "claim": "b"},
            ]
        ),
        verifier_call("H1", {**CONFIRMED, "cwe": ["CWE-476"]}),
        verifier_call("H2", {**CONFIRMED, "cwe": ["CWE-787"]}),
    )
    result = replay_thinking.replay_file(pipeline(), report, log)

    assert len(result["findings"]) == 1
    assert result["metadata"]["claim_merges"]


def test_the_replayed_report_is_serialisable(tmp_path):
    """The harness output is fed straight back into the evaluator."""
    report = phase1_report(_write(VULNERABLE))
    log = entry(scanner_call([HYPOTHESIS]), verifier_call("H1", CONFIRMED))
    result = replay_thinking.replay_file(pipeline(), report, log)

    json.dumps(result)
    assert result["source"] == report["source"]


def _write(code: str, name: str = "sample.py") -> Path:
    import tempfile

    path = Path(tempfile.mkdtemp()) / name
    path.write_text(code)
    return path