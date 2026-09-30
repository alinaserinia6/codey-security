"""LLM-misbehavior robustness: bad replies and error codes must not stop a run.

When the model returns garbage (non-JSON-shaped dicts, text confidences,
string lines) or the transport raises (HTTP errors, timeouts, connection
resets), every harness layer is required to degrade to an ERROR record and
continue with the next sample. These tests pin that contract without any
network access by stubbing the agent.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import run_llm_only_benchmark as llm_only
from evaluate_llm_only import build_predictions, load_records
from phase3.extract_predictions import (
    predictions_from_phase1,
    predictions_from_phase2,
)


class StubAgent:
    """Stands in for SecurityAgent.analyze without touching the network."""

    def __init__(self, value=None, error=None):
        self.value = value
        self.error = error
        self.model_id = "stub-model"
        self.base_url = "http://stub:1234"

    async def analyze(self, packet, system_prompt=None):
        if self.error is not None:
            raise self.error
        return self.value


def _sample(tmp_path: Path, code: str = "x = 1\n") -> dict:
    path = tmp_path / "sample.py"
    path.write_text(code)
    return {"sample_id": "s1", "file": str(path)}


def _judge(agent, sample) -> dict:
    sem = asyncio.Semaphore(4)
    return asyncio.run(llm_only._judge(agent, sem, sample))


# -- _judge degradations -----------------------------------------------------


def test_transport_error_becomes_error_record(tmp_path):
    record = _judge(StubAgent(error=ConnectionError("refused")), _sample(tmp_path))
    assert record["decision"] == "ERROR"
    assert "ConnectionError" in record["error"]


def test_http_status_error_becomes_error_record(tmp_path):
    # HTTP error codes arrive as SDK exceptions that are NOT OSError
    # subclasses; they must still be caught per sample.
    record = _judge(StubAgent(error=RuntimeError("500 Internal Server Error")), _sample(tmp_path))
    assert record["decision"] == "ERROR"
    assert "500" in record["error"]


def test_non_dict_reply_becomes_error_record(tmp_path):
    record = _judge(StubAgent(value=["not", "a", "dict"]), _sample(tmp_path))
    assert record["decision"] == "ERROR"


def test_text_confidence_is_clamped_not_fatal(tmp_path):
    record = _judge(
        StubAgent(value={"decision": "CONFIRMED", "confidence": "high", "cwe": ["CWE-78"]}),
        _sample(tmp_path),
    )
    assert record["decision"] == "CONFIRMED"
    assert record["confidence"] == 0.0


def test_string_cwe_and_line_are_coerced(tmp_path):
    record = _judge(
        StubAgent(
            value={
                "decision": "CONFIRMED",
                "confidence": 0.9,
                "cwe": "CWE-78",
                "source_location": "sample.py:abc",
            }
        ),
        _sample(tmp_path),
    )
    assert record["decision"] == "CONFIRMED"
    assert record["cwe"] == ["CWE-78"]
    assert record["line"] is None


def test_unknown_decision_word_becomes_uncertain(tmp_path):
    record = _judge(StubAgent(value={"decision": "MAYBE"}), _sample(tmp_path))
    assert record["decision"] == "UNCERTAIN"


def test_missing_file_becomes_error_record(tmp_path):
    record = _judge(
        StubAgent(value={"decision": "CONFIRMED"}),
        {"sample_id": "gone", "file": str(tmp_path / "nope.py")},
    )
    assert record["decision"] == "ERROR"
    assert "read failed" in record["error"]


def test_judge_labels_the_thinking_log_with_the_sample(tmp_path):
    """The sidecar trace is keyed by sample, not by the packet's dummy name."""
    from agents import thinking_log

    seen = {}

    class ScopedStub(StubAgent):
        async def analyze(self, packet, system_prompt=None):
            seen.update(thinking_log.current_scope())
            return {"decision": "REJECTED"}

    sample = _sample(tmp_path)
    record = _judge(ScopedStub(value={"decision": "REJECTED"}), sample)

    assert record["decision"] == "REJECTED"
    assert seen == {
        "id": sample["sample_id"],
        "file": sample["file"],
        "role": "llm_only",
    }


def test_thinking_out_path_sits_next_to_the_predictions():
    assert (
        llm_only.thinking_out_path("results/exp_B.jsonl")
        == "results/exp_B.thinking.json"
    )
    assert (
        llm_only.thinking_out_path("results/exp_B.jsonl", "elsewhere/t.json")
        == "elsewhere/t.json"
    )


# -- arg validation ----------------------------------------------------------


def test_concurrency_zero_rejected():
    args = llm_only.build_parser().parse_args(
        ["--dataset", "x", "--out", "y", "--concurrency", "0"]
    )
    with pytest.raises(ValueError):
        llm_only.validate_args(args)


def test_negative_limit_rejected():
    args = llm_only.build_parser().parse_args(
        ["--dataset", "x", "--out", "y", "--limit", "-3"]
    )
    with pytest.raises(ValueError):
        llm_only.validate_args(args)


def test_nonpositive_timeout_rejected():
    args = llm_only.build_parser().parse_args(
        ["--dataset", "x", "--out", "y", "--timeout", "0"]
    )
    with pytest.raises(ValueError):
        llm_only.validate_args(args)


# -- terminal-visible errors -------------------------------------------------


def test_emit_errors_prints_sample_id_and_text(capsys):
    from phase3.runner import emit_errors

    emit_errors("s1", ["boom", "bust"])
    emit_errors("s2", [])
    captured = capsys.readouterr()
    assert "ERROR s1: boom" in captured.err
    assert "ERROR s1: bust" in captured.err
    assert "s2" not in captured.err


def test_collect_report_errors_handles_both_shapes():
    import codey_security

    reports = [
        {"sample_id": "a", "skipped": True, "reason": "missing file"},
        {"sample_id": "b",
         "report": {"errors": ["bandit crashed"]}},
        {"sample_id": "c",
         "phase1": {"errors": []},
         "phase2": {"errors": ["scanner: timeout"]}},
        {"sample_id": "d",
         "phase1": {"errors": []},
         "phase2": {"errors": [], "decisions": []}},
    ]
    pairs = codey_security._collect_report_errors(reports)
    assert ("a", "skipped: missing file") in pairs
    assert ("b", "bandit crashed") in pairs
    assert ("c", "phase2: scanner: timeout") in pairs
    assert all(sample != "d" for sample, _ in pairs)


def test_transport_error_carries_endpoint_context():
    from agents.security_agent import SecurityAgent

    agent = SecurityAgent.__new__(SecurityAgent)
    agent.transport = "opencode"
    agent.base_url = "http://127.0.0.1:4096"
    agent.model_id = "stub-model"
    agent.provider_id = "opencode"
    wrapped = agent._wrap_transport_error(ConnectionError("refused"), "chat")
    assert "http://127.0.0.1:4096" in str(wrapped)
    assert "stub-model" in str(wrapped)
    assert "ConnectionError" in str(wrapped)


# -- evaluate_llm_only -------------------------------------------------------


def test_load_records_skips_bad_lines(tmp_path):
    path = tmp_path / "preds.jsonl"
    path.write_text(
        '{"sample_id": "a", "decision": "CONFIRMED", "cwe": ["CWE-78"]}\n'
        "this is not json\n"
        '{"no_sample_id": true}\n'
        '{"sample_id": "b", "decision": "REJECTED"}\n'
    )
    records = load_records(path)
    assert sorted(r["sample_id"] for r in records) == ["a", "b"]


def test_load_records_missing_file_raises_filenotfound(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_records(tmp_path / "absent.jsonl")


def test_build_predictions_coerces_garbage(tmp_path):
    records = [
        {"sample_id": "a", "decision": "CONFIRMED", "line": "twelve",
         "confidence": "high", "cwe": "CWE-78", "file": "a.py"},
        {"sample_id": "b", "decision": "CONFIRMED", "line": 5,
         "confidence": 0.7, "cwe": ["CWE-94"], "file": "b.py"},
        {"sample_id": "c", "decision": "REJECTED"},
    ]
    preds = build_predictions(records, "llm_only")
    assert len(preds) == 2
    assert preds[0].line is None
    assert preds[0].confidence == 0.0
    assert preds[0].cwe == ["CWE-78"]
    assert preds[1].line == 5


# -- extract_predictions -----------------------------------------------------


def test_phase1_extraction_survives_malformed_findings():
    report = {
        "source": "x.c",
        "findings": [
            {"tool": "flawfinder", "file": "x.c", "line": "bad",
             "confidence": "high", "cwe": "CWE-120", "fingerprint": "f1"},
            "not-a-dict",
            {"tool": "bandit", "file": "x.py", "line": 3,
             "confidence": 0.5, "cwe": ["CWE-78"], "fingerprint": "f2"},
        ],
    }
    preds = predictions_from_phase1(report, "s1")
    assert len(preds) == 2
    assert preds[0].line is None
    assert preds[0].cwe == ["CWE-120"]
    assert preds[1].line == 3


def test_phase2_extraction_survives_malformed_decisions():
    report = {
        "source": "x.py",
        "decisions": [
            {"status": "CONFIRMED", "file": "x.py", "line": "NaN",
             "confidence": None, "cwe": ["CWE-78"]},
            {"status": "CONFIRMED", "file": "x.py", "line": 7,
             "confidence": 0.9, "cwe": ["CWE-94"]},
        ],
    }
    preds = predictions_from_phase2(report, "s1")
    assert len(preds) == 2
    assert preds[0].line is None
    assert preds[1].line == 7
