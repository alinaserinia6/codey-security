"""The RESULT block has to time the whole leg, not just its last step.

B runs in two steps -- the prediction run, then the evaluation that scores it
-- and its row is printed by the evaluation step, because that is where the
metrics appear. Timing only that step reported the expensive leg as
``ok (0s)``, which reads as "the model was free". The row has to carry the
prediction time as well, and say where the number came from.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

STEP_SECONDS = {
    "subset": 1.0,
    "A-sub": 2.0,
    "B": 160.0,
    "B-eval": 3.0,
    "C": 100.0,
    "D": 100.0,
}


def _load_runner():
    """Import the script by path; it is not part of the package."""
    spec = importlib.util.spec_from_file_location(
        "run_benchmarks", ROOT / "scripts" / "run_benchmarks.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["run_benchmarks"] = module
    spec.loader.exec_module(module)
    return module


def test_b_row_reports_predict_and_eval_time(monkeypatch, capsys):
    rb = _load_runner()

    # No subprocess, no network, no files: the runner is exercised for its
    # report assembly only, which is the behaviour under test.
    monkeypatch.setattr(
        rb, "run_step",
        lambda name, argv, env=None, timeout=None:
            (True, STEP_SECONDS.get(name, 1.0), ["ok"]),
    )
    monkeypatch.setattr(rb, "read_metrics", lambda path: {
        "tp": 13, "fp": 15, "fn": 9, "tn": 25,
        "precision": 0.4643, "recall": 0.5909, "f1": 0.52,
    })
    monkeypatch.setattr(rb, "llm_reachable", lambda timeout=8: (True, "fake"))
    for name in ("LLM_TIMEOUT", "LLM_MAX_ATTEMPTS", "LLM_THINKING_PRINT"):
        monkeypatch.setenv(name, "0")

    rc = rb.main(["--suite", "llm", "--llm-source", "vulnllm_r_c_dataflow",
                  "--llm-limit", "12", "--tag", "timing_check"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "failures=0" in out
    b_row = next(line for line in out.splitlines()
                 if line.startswith("B llm-only "))
    assert "163s = 160s predict + 3s eval" in b_row

    # A single-step leg keeps the plain format -- nothing to break down.
    c_row = next(line for line in out.splitlines()
                 if line.startswith("C static+LLM "))
    assert "(100s)" in c_row
    assert "predict" not in c_row
