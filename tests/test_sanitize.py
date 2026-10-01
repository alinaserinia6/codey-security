"""The sanitizer is what keeps the LLM-only baseline honest.

If label-leaking comments or ``bad``/``good`` scenario identifiers survive,
the model can read the answer out of the file and the comparison against the
static baselines is meaningless.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from phase2.sanitize import (
    neutral_name,
    sanitize_identifiers,
    sanitize_source,
    sanitize_value,
    strip_comments,
)

ROOT = Path(__file__).resolve().parents[1]

LABEL_LEAK_SAMPLE = """\
/* CWE190 - Integer Overflow
 * POTENTIAL FLAW: the increment can wrap around
 */
#include "std_c.h"

void CWE190_Integer_Overflow__int_rand_45_bad(void)
{
    int badData = INT_MAX;
    int *badPtr = &badData;
    /* good variant uses a checked increment */
    goodG2B();
    return;
}
"""


def test_comments_are_removed_but_lines_are_kept():
    text = strip_comments(LABEL_LEAK_SAMPLE, "c", path="sample.c")
    assert "POTENTIAL FLAW" not in text
    assert "CWE190 - Integer Overflow" not in text
    assert len(text.splitlines()) == len(LABEL_LEAK_SAMPLE.splitlines())


def test_scenario_identifiers_are_neutralized():
    text = sanitize_source(LABEL_LEAK_SAMPLE, "c", path="sample.c")
    assert "CWE190_Integer_Overflow__int_rand_45_bad" not in text
    assert "badData" not in text
    assert "badPtr" not in text
    assert "goodG2B" not in text
    assert "sym_" in text


def test_cwe_references_are_not_rewritten():
    # ``CWE-190`` / ``CWE190`` (no underscore after the digits) must survive:
    # tool messages and the prediction CWE list rely on them.
    assert sanitize_identifiers("reported CWE-190 and CWE190 here") == (
        "reported CWE-190 and CWE190 here"
    )


def test_neutral_names_are_stable_and_collision_free_per_identifier():
    assert neutral_name("badData") == neutral_name("badData")
    assert len({neutral_name(x) for x in ("bad", "good", "badSink")}) == 3


def test_sanitize_value_walks_nested_structures():
    packet = {
        "members": [{"name": "CWE190_Integer_Overflow__int_45_bad"}],
        "cwe": ["CWE-190"],
        "source_context": {"snippet": "int badData;"},
        "count": 3,
        "flag": True,
        "missing": None,
    }
    out = sanitize_value(packet)
    assert out["members"][0]["name"].startswith("sym_")
    assert out["source_context"]["snippet"].startswith("int sym_")
    assert out["cwe"] == ["CWE-190"]
    assert out["count"] == 3 and out["flag"] is True and out["missing"] is None


def test_evaluator_script_loads_and_filters_records(tmp_path):
    spec = importlib.util.spec_from_file_location(
        "evaluate_llm_only", ROOT / "scripts" / "evaluate_llm_only.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["evaluate_llm_only"] = module
    try:
        spec.loader.exec_module(module)

        jsonl = tmp_path / "run.jsonl"
        jsonl.write_text(
            "\n".join(
                [
                    '{"sample_id": "a", "file": "a.c", "decision": "CONFIRMED",'
                    ' "cwe": ["CWE-120"], "line": 12, "confidence": 0.9}',
                    '{"sample_id": "b", "file": "b.c", "decision": "REJECTED"}',
                    '{"sample_id": "a", "file": "a.c", "decision": "REJECTED"}',
                    '{"sample_id": "c", "file": "c.c", "decision": "CONFIRMED"}',
                    '{"sample_id": "c", "file": "c.c", "decision": "ERROR",'
                    ' "error": "TimeoutError"}',
                ]
            ),
            encoding="utf-8",
        )
        records = module.load_records(jsonl)
        # resume appends duplicates; the newest record per sample wins
        assert {r["sample_id"] for r in records} == {"a", "b", "c"}
        by_id = {r["sample_id"]: r for r in records}
        assert by_id["a"]["decision"] == "REJECTED"
        # ...but a transport error must not hide an existing judgement
        assert by_id["c"]["decision"] == "CONFIRMED"

        predictions = module.build_predictions(
            [{"sample_id": "a", "file": "a.c", "decision": "CONFIRMED",
              "cwe": ["CWE-120"], "line": 12, "confidence": 0.5},
             {"sample_id": "b", "file": "b.c", "decision": "UNCERTAIN"}],
            "llm_only",
        )
        assert len(predictions) == 1
        assert predictions[0].sample_id == "a" and predictions[0].vulnerable
        assert predictions[0].line == 12 and predictions[0].source == "llm_only"
    finally:
        sys.modules.pop("evaluate_llm_only", None)
