"""Reporting guarantees of the taint evidence evaluator.

The evaluator's job is not only to produce a recall number but to make the
shape of that number honest. Two of these tests exist because a defect in the
analyzer was invisible in the totals: a language with no taint pattern table
yields no chains, and no chains fold into the same true-negative bucket as a
correctly analysed safe file. The report has to keep that distinction visible.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load_evaluator():
    """Import the script by path; it is not part of the package."""
    spec = importlib.util.spec_from_file_location(
        "eval_taint_evidence", ROOT / "scripts" / "eval_taint_evidence.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["eval_taint_evidence"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def evaluator():
    return _load_evaluator()


def _write(tmp_path: Path, name: str, code: str) -> Path:
    path = tmp_path / name
    path.write_text(textwrap.dedent(code), encoding="utf-8")
    return path


def test_report_splits_results_by_language(evaluator, tmp_path: Path):
    c = _write(
        tmp_path,
        "vuln.c",
        """
        void copy_in(char *in) { char buf[16]; strcpy(buf, in); }
        """,
    )
    cpp = _write(
        tmp_path,
        "vuln.cpp",
        """
        void copy_in(char *in) { char buf[16]; strcpy(buf, in); }
        """,
    )
    safe = _write(tmp_path, "safe.c", "int add(int a, int b) { return a + b; }\n")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "samples": [
                    {"sample_id": "c", "file": str(c), "vulnerable": True, "language": "c"},
                    {"sample_id": "cpp", "file": str(cpp), "vulnerable": True, "language": "cpp"},
                    {"sample_id": "safe", "file": str(safe), "vulnerable": False, "language": "c"},
                ]
            }
        ),
        encoding="utf-8",
    )

    result = evaluator.evaluate(manifest, None)

    assert result["languages_without_evidence_support"] == {}
    per_language = result["per_language"]
    assert per_language["c"]["samples"] == 2
    assert per_language["cpp"]["samples"] == 1
    # The C++ sample is analysed rather than being counted as safe for free.
    assert per_language["cpp"]["tp"] == 1


def test_unsupported_extension_is_counted_as_an_error(evaluator, tmp_path: Path):
    """A file the structural analyzer cannot read is not a true negative.

    It is reported in `errors` and `failures`, so it is visible rather than
    quietly inflating the benign flag rate.
    """
    src = _write(tmp_path, "main.go", "package main\n\nfunc main() {}\n")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "samples": [
                    {
                        "sample_id": "go",
                        "file": str(src),
                        "vulnerable": False,
                        "language": "go",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    result = evaluator.evaluate(manifest, None)

    assert result["errors"] == 1
    assert result["failures"] and "Unsupported source extension" in result["failures"][0]
    assert result["metrics"]["any_source_to_sink_path"]["tn"] == 0


def test_every_supported_language_has_taint_patterns():
    """The invariant that keeps the silent-scoring hole shut.

    The structural analyzer accepting a language that the taint tables do not
    cover would mean every file in that language produces no chains and is
    scored as a true negative. When a language is added to one side, this
    fails until the other side catches up.
    """
    from analyzers.structural_analyzer import (
        C_EXTENSIONS,
        CPP_EXTENSIONS,
        PYTHON_EXTENSIONS,
        StructuralAnalyzer,
    )
    from analyzers.taint import SOURCE_PATTERNS, taint_language

    supported = {
        StructuralAnalyzer.detect_language(Path(f"sample{ext}"))
        for ext in (*C_EXTENSIONS, *CPP_EXTENSIONS, *PYTHON_EXTENSIONS)
    }
    uncovered = {
        language
        for language in supported
        if taint_language(language) not in SOURCE_PATTERNS
    }
    assert not uncovered, f"no taint pattern table for {sorted(uncovered)}"
    # C++ has no table of its own and must resolve to the C one.
    assert taint_language("cpp") == "c"
    assert taint_language("python") == "python"


def test_manifest_still_carries_the_flat_metrics(evaluator, tmp_path: Path):
    """The per-language split is additive; existing keys are unchanged."""
    src = _write(
        tmp_path,
        "vuln.c",
        """
        void copy_in(char *in) { char buf[16]; strcpy(buf, in); }
        """,
    )
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {"samples": [{"sample_id": "c", "file": str(src), "vulnerable": True}]}
        ),
        encoding="utf-8",
    )

    result = evaluator.evaluate(manifest, None)

    assert "any_source_to_sink_path" in result["metrics"]
    assert "source_to_sink_path_without_mitigation" in result["metrics"]
    assert result["metrics"]["any_source_to_sink_path"]["tp"] == 1


def test_failed_baseline_scan_is_not_scored_as_negative(
    evaluator, tmp_path: Path, monkeypatch
):
    """An unavailable baseline is missing evidence, not a benign verdict."""
    good = _write(tmp_path, "good.c", "int add(int a, int b) { return a + b; }\n")
    bad = _write(
        tmp_path,
        "bad.c",
        "void copy_in(char *in) { char buf[16]; strcpy(buf, in); }\n",
    )
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "samples": [
                    {
                        "sample_id": "good",
                        "file": str(good),
                        "vulnerable": False,
                    },
                    {"sample_id": "bad", "file": str(bad), "vulnerable": True},
                ]
            }
        ),
        encoding="utf-8",
    )

    class FlakyRunner:
        def scan(self, path):
            if path.name == "bad.c":
                return [], ["simulated baseline failure"]
            return [], []

    monkeypatch.setitem(evaluator._BASELINE_RUNNERS, "flawfinder", FlakyRunner)
    result = evaluator.evaluate(manifest, None, baseline="flawfinder")

    assert result["metrics"]["any_source_to_sink_path"]["tp"] == 1
    assert result["baseline"]["metrics"] == {
        "tp": 0,
        "fp": 0,
        "fn": 0,
        "tn": 1,
        "precision": 0.0,
        "recall": 0.0,
        "f1": 0.0,
        "benign_flag_rate": 0.0,
    }
    assert result["baseline"]["unavailable_samples"] == 1
    assert result["baseline"]["tool_errors"] == ["bad.c: simulated baseline failure"]
