"""Provenance: a result file must describe the run that produced it.

The benchmark's own limitations note a configuration-opacity problem: the
transport resolved ``temperature`` and ``reasoning_effort`` on every request
and no result file recorded either, so a claim that a rerun "should reproduce"
was unfalsifiable.  These tests pin the repair -- one resolver shared by the
transport and the writers, sampling knobs in the phase3/``full`` provenance
blocks, per-record sampling fields in Experiment B's JSONL, and an evaluation
that reads them back from the file instead of from today's environment.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from agents.openai_compat import OpenAICompat, sampling_settings  # noqa: E402
from codey_security import _provenance_block, _sampling_provenance  # noqa: E402
from env_config import Config, ScenarioConfig  # noqa: E402
from evaluate_llm_only import _float_or_none, _int_or_none, main  # noqa: E402


def _compat(**kwargs) -> OpenAICompat:
    return OpenAICompat(base_url="https://api.example.com/v1", model_id="m", **kwargs)


# -- one resolver, used by the transport and by every writer -----------------


def test_an_explicit_temperature_beats_the_environment(monkeypatch) -> None:
    monkeypatch.setenv("LLM_TEMPERATURE", "0.2")
    assert sampling_settings(0.0)["temperature"] == 0.0
    assert sampling_settings()["temperature"] == 0.2


def test_unset_knobs_mean_the_field_is_not_sent(monkeypatch) -> None:
    monkeypatch.delenv("LLM_TEMPERATURE", raising=False)
    monkeypatch.delenv("LLM_REASONING_EFFORT", raising=False)
    settings = sampling_settings()
    assert settings["temperature"] is None
    assert settings["reasoning_effort"] is None


def test_an_env_effort_is_stripped_not_echoed(monkeypatch) -> None:
    monkeypatch.setenv("LLM_REASONING_EFFORT", "  minimal  ")
    assert sampling_settings()["reasoning_effort"] == "minimal"


def test_effective_settings_follow_a_dropped_effort() -> None:
    compat = _compat(temperature=0.0, reasoning_effort="high")
    assert compat.effective_settings() == {
        "temperature": 0.0,
        "reasoning_effort": "high",
        "reasoning_effort_dropped": False,
    }
    compat._effort_dropped = True
    effective = compat.effective_settings()
    assert effective["reasoning_effort"] is None
    assert effective["reasoning_effort_dropped"] is True


# -- the phase3 / full provenance blocks -------------------------------------


def test_a_static_only_run_claims_no_sampling_knobs() -> None:
    assert _sampling_provenance("phase1") == {
        "temperature": None,
        "reasoning_effort": None,
    }


def test_a_model_backed_run_records_what_it_sent(monkeypatch) -> None:
    monkeypatch.setenv("LLM_TEMPERATURE", "0.1")
    monkeypatch.setenv("LLM_REASONING_EFFORT", "minimal")
    assert _sampling_provenance("phase2") == {
        "temperature": 0.1,
        "reasoning_effort": "minimal",
    }


# -- the shared provenance block --------------------------------------------


def test_a_phase3_block_records_the_time_it_actually_took() -> None:
    scenario = ScenarioConfig(
        mode="phase1", dataset="datasets/x.json", require_cwe_match=False
    )
    block = _provenance_block(
        scenario, "datasets/x.json", 600, Config(), elapsed_seconds=12.5
    )
    assert block["elapsed_seconds"] == 12.5
    assert block["dataset_samples"] == 600
    assert block["require_cwe_match"] is False
    assert block["model"] is None
    assert block["temperature"] is None
    assert block["tool_versions"] and block["python_version"]
    # The duration is read before the tool versions, the order the phase3
    # result has always had.
    keys = list(block)
    assert keys.index("elapsed_seconds") < keys.index("tool_versions")


def test_the_full_block_omits_a_duration_it_cannot_define() -> None:
    # `full` spans Phase 1 + 2 + 3, so an `elapsed_seconds` here would be a
    # different quantity from the one a phase3 result reports under the name.
    scenario = ScenarioConfig(mode="phase2", dataset="datasets/x.json")
    block = _provenance_block(scenario, "datasets/x.json", 600, Config())
    assert "elapsed_seconds" not in block
    assert block["mode"] == "phase2"
    assert block["model"] == Config().llm_model_id
    assert block["base_url"] == Config().llm_base_url
    assert block["finished_at"]


# -- Experiment B: the settings travel with the verdict ----------------------


def _manifest(tmp_path: Path) -> Path:
    payload = {
        "dataset": "provenance-test",
        "samples": [
            {
                "sample_id": "p1",
                "file": str(tmp_path / "p1.c"),
                "vulnerable": True,
                "cwe": ["CWE-121"],
                "line": None,
                "function": "bad",
                "language": "c",
            },
            {
                "sample_id": "n1",
                "file": str(tmp_path / "n1.c"),
                "vulnerable": False,
                "cwe": [],
                "line": None,
                "function": "good",
                "language": "c",
            },
        ],
    }
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _record(sample_id: str, decision: str, **extra) -> dict:
    record = {
        "sample_id": sample_id,
        "file": f"/tmp/{sample_id}.c",
        "language": "c",
        "decision": decision,
        "cwe": ["CWE-121"] if decision == "CONFIRMED" else [],
        "line": None,
        "confidence": 0.9 if decision == "CONFIRMED" else 0.0,
        "severity": "UNKNOWN",
        "rationale": "",
        "error": "",
        "elapsed": 1.0,
        "model": "m",
        "base_url": "https://api.example.com/v1",
    }
    record.update(extra)
    return record


def _run_evaluate(tmp_path: Path, records: list[dict]) -> dict:
    manifest = _manifest(tmp_path)
    predictions_path = tmp_path / "predictions.jsonl"
    predictions_path.write_text(
        "\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8"
    )
    out_path = tmp_path / "result.json"
    argv = [
        "evaluate_llm_only.py",
        "--dataset",
        str(manifest),
        "--predictions",
        str(predictions_path),
        "--out",
        str(out_path),
        "--experiment",
        "llm_only",
    ]
    original_argv = sys.argv
    sys.argv = argv
    try:
        main()
    finally:
        sys.argv = original_argv
    return json.loads(out_path.read_text(encoding="utf-8"))


def test_the_evaluation_reads_settings_back_from_the_file(
    tmp_path, monkeypatch
) -> None:
    # Today's environment disagrees with what the run used; the file must win.
    monkeypatch.setenv("LLM_TEMPERATURE", "0.9")
    monkeypatch.setenv("LLM_REASONING_EFFORT", "high")
    result = _run_evaluate(
        tmp_path,
        [
            _record(
                "p1",
                "CONFIRMED",
                temperature=0.2,
                reasoning_effort="minimal",
                concurrency=12,
            ),
            _record(
                "n1",
                "ERROR",
                temperature=0.2,
                reasoning_effort="minimal",
                concurrency=12,
            ),
        ],
    )
    provenance = result["metadata"]["provenance"]
    assert provenance["temperatures_in_file"] == [0.2]
    assert provenance["reasoning_efforts_in_file"] == ["minimal"]
    assert provenance["concurrencies_in_file"] == [12]
    assert provenance["reasoning_effort_dropped_records"] is None


def test_a_dropped_effort_is_counted_not_hidden(tmp_path) -> None:
    result = _run_evaluate(
        tmp_path,
        [
            _record("p1", "CONFIRMED", temperature=0.2, reasoning_effort=None,
                    reasoning_effort_dropped=True, concurrency=8),
            _record("n1", "ERROR", temperature=0.2, reasoning_effort=None,
                    reasoning_effort_dropped=True, concurrency=8),
        ],
    )
    provenance = result["metadata"]["provenance"]
    assert provenance["reasoning_effort_dropped_records"] == 2
    # A dropped field is recorded as absent, not as a setting that was sent.
    assert provenance["reasoning_efforts_in_file"] is None
    assert provenance["temperatures_in_file"] == [0.2]


def test_records_written_before_this_fix_record_nothing(tmp_path) -> None:
    result = _run_evaluate(
        tmp_path,
        [_record("p1", "CONFIRMED"), _record("n1", "ERROR")],
    )
    provenance = result["metadata"]["provenance"]
    assert provenance["temperatures_in_file"] is None
    assert provenance["reasoning_efforts_in_file"] is None
    assert provenance["concurrencies_in_file"] is None


def test_zero_is_a_temperature_that_must_survive() -> None:
    assert _float_or_none(0.0) == 0.0
    assert _float_or_none(None) is None
    assert _float_or_none("nope") is None
    assert _int_or_none(0) == 0
    assert _int_or_none(None) is None
