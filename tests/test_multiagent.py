"""Scanner -> Verifier orchestration.

The pipeline is exercised against a stub agent so the control flow, the
reject-by-default rule and the report schema are all pinned without a model in
the loop. The stub records what each agent was shown, which is how the tests
check the verifier actually receives the source-to-sink evidence rather than
just the scanner's claim.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest

from analyzers.structural_analyzer import StructuralAnalyzer
from phase2.models import Hypothesis
from phase2.multiagent import MultiAgentConfig, MultiAgentPipeline

VULNERABLE = '''
import subprocess
import sys

def run_user_command(command):
    subprocess.call(command, shell=True)

if __name__ == "__main__":
    run_user_command(sys.argv[1])
'''

BENIGN = '''
import subprocess

def list_files(directory):
    subprocess.call(["ls", "-l", directory])
'''

CODE_INJECTION = '''
def compute(expression):
    return eval(expression)
'''


class StubAgent:
    """Returns canned responses and records the prompts it was given."""

    def __init__(
        self,
        scan_response: Dict[str, Any],
        verify_responses: List[Dict[str, Any]] | None = None,
    ) -> None:
        self.scan_response = scan_response
        self.verify_responses = verify_responses or []
        self.prompts: List[Tuple[str, Dict[str, Any]]] = []

    async def __call__(self, system: str, packet: Dict[str, Any]) -> Dict[str, Any]:
        self.prompts.append((system, packet))
        if packet.get("role") == "scanner":
            return self.scan_response
        calls = [p for _, p in self.prompts if p.get("role") == "verifier"]
        index = len(calls) - 1
        if index < len(self.verify_responses):
            return self.verify_responses[index]
        return {"decision": "REJECTED", "confidence": 0.9, "explanation": "no path"}


def write(tmp_path: Path, code: str, name: str = "sample.py") -> Path:
    path = tmp_path / name
    path.write_text(code)
    return path


def phase1_report(path: Path) -> Dict[str, Any]:
    structure = StructuralAnalyzer().analyze_file(path)
    return {
        "source": str(path),
        "language": structure["language"],
        "findings": [],
        "metadata": {"structure": structure},
    }


def run(agent: StubAgent, report: Dict[str, Any], **cfg) -> Dict[str, Any]:
    import asyncio

    pipeline = MultiAgentPipeline(agent, config=MultiAgentConfig(**cfg))
    return asyncio.run(pipeline.analyze_file(report))


# -- hypothesis parsing --------------------------------------------------

def test_parses_documented_schema():
    items = MultiAgentPipeline._parse_hypotheses(
        {"hypotheses": [{"cwe": "CWE-78", "line": 5, "claim": "argv to shell"}]}
    )
    assert len(items) == 1
    assert items[0].cwe == "CWE-78"
    assert items[0].line == 5


@pytest.mark.parametrize(
    "raw",
    [
        [{"cwe": "CWE-78", "claim": "x"}],
        {"findings": [{"cwe": "CWE-78", "claim": "x"}]},
        {"candidates": [{"cwe": "CWE-78", "claim": "x"}]},
    ],
)
def test_accepts_common_response_shapes(raw):
    assert len(MultiAgentPipeline._parse_hypotheses(raw)) == 1


@pytest.mark.parametrize("raw", [None, "", "not json", 42, {"hypotheses": []}])
def test_rejects_unusable_scanner_output(raw):
    assert MultiAgentPipeline._parse_hypotheses(raw) == []


def test_drops_empty_hypotheses():
    raw = {"hypotheses": [{"cwe": "", "claim": ""}, {"cwe": "CWE-78", "claim": "x"}]}
    assert len(MultiAgentPipeline._parse_hypotheses(raw)) == 1


def test_hypothesis_tolerates_bad_types():
    hypothesis = Hypothesis.from_dict({"cwe": ["CWE-89"], "line": "nope"})
    assert hypothesis.cwe == "CWE-89"
    assert hypothesis.line is None


# -- confirmed path ------------------------------------------------------

def test_confirmed_hypothesis_becomes_a_report_finding(tmp_path):
    path = write(tmp_path, VULNERABLE)
    agent = StubAgent(
        {
            "hypotheses": [
                {
                    "cwe": "CWE-78",
                    "line": 6,
                    "claim": "argv reaches subprocess.call with shell=True",
                    "suspected_source": "sys.argv",
                    "suspected_sink": "subprocess.call",
                }
            ]
        },
        [
            {
                "decision": "CONFIRMED",
                "chain_verified": True,
                "confidence": 0.9,
                "cwe": ["CWE-78"],
                "severity": "HIGH",
                "explanation": "argv[1] is passed to a shell.",
                "source_location": f"{path}:6",
            }
        ],
    )
    result = run(agent, phase1_report(path))

    assert len(result["findings"]) == 1
    finding = result["findings"][0]
    assert finding["cwe"] == "CWE-78"
    assert finding["severity"] == "HIGH"
    assert finding["chain_verified"] is True
    assert finding["file"] == str(path)
    assert finding["line"] == 6
    # CWE-78 has no catalogued real-world example, so the reference list holds
    # the MITRE class page and the CVE list is empty. The field is always
    # present, and never invented to fill it.
    assert finding["related_cves"] == []
    assert finding["references"], "a confirmed finding must carry references"
    assert any("cwe.mitre.org" in ref for ref in finding["references"])
    assert finding["sink"], "the report must cite the sink it confirmed"
    assert finding["source"]
    assert result["metadata"]["decision_counts"]["CONFIRMED"] == 1


@pytest.mark.parametrize(
    ("location", "expected_line"),
    [
        # The schema shows the field as "file:line"; a terse model sometimes
        # answers with that placeholder itself.
        ("file:183", 183),
        # The basename of the file under analysis still identifies it.
        ("sample.py:6", 6),
        # A name the report cannot check: the line survives, the file does not.
        ("elsewhere.c:7", 7),
        # No usable line, but a usable file.
        ("sample.py:abc", None),
    ],
)
def test_report_names_the_file_under_analysis_not_a_model_location(
    tmp_path, location, expected_line
):
    path = write(tmp_path, VULNERABLE)
    agent = StubAgent(
        {"hypotheses": [{"cwe": "CWE-78", "line": 6, "claim": "argv to shell"}]},
        [
            {
                "decision": "CONFIRMED",
                "confidence": 0.9,
                "chain_verified": True,
                "cwe": ["CWE-78"],
                "severity": "HIGH",
                "explanation": "argv[1] is passed to a shell.",
                "source_location": location,
            }
        ],
    )
    result = run(agent, phase1_report(path))

    assert len(result["findings"]) == 1
    finding = result["findings"][0]
    assert finding["file"] == str(path)
    assert finding["line"] == expected_line


def test_verifier_is_shown_the_dataflow_chain(tmp_path):
    path = write(tmp_path, VULNERABLE)
    agent = StubAgent(
        {"hypotheses": [{"cwe": "CWE-78", "line": 6, "claim": "x"}]},
        [{"decision": "CONFIRMED", "confidence": 0.8, "chain_verified": True}],
    )
    run(agent, phase1_report(path))

    verifier_packets = [p for s, p in agent.prompts if p.get("role") == "verifier"]
    assert verifier_packets
    chains = verifier_packets[0]["dataflow_chains"]
    assert chains, "the verifier must receive the recovered path"
    assert any(c["source_expression"] for c in chains)


def test_scanner_receives_structural_and_tool_evidence(tmp_path):
    path = write(tmp_path, VULNERABLE)
    agent = StubAgent({"hypotheses": []})
    run(agent, phase1_report(path))

    scanner = next(p for s, p in agent.prompts if p.get("role") == "scanner")
    assert scanner["structural"]["language"] == "python"
    assert scanner["static_tool_findings"] == []
    assert scanner["source_context"]["available"] is True


def test_verifier_reads_the_real_file_when_the_path_is_sanitised(tmp_path):
    """Regression: the sanitiser rewrites leaking path segments.

    ``.../good/sample.py`` is shown to the model as ``.../sym_XXXX/sample.py``
    so the variant cannot be read off the filename. Reading the disk with that
    rewritten path raised ENOENT, so the verifier was shown an empty snippet
    for every label-bearing sample and answered UNCERTAIN by default. The
    packet keeps the sanitised path; the file read must use the real one.
    """
    directory = tmp_path / "good"
    directory.mkdir()
    path = directory / "sample.py"
    path.write_text(VULNERABLE)

    agent = StubAgent(
        {"hypotheses": [{"cwe": "CWE-78", "line": 6, "claim": "x"}]},
        [{"decision": "REJECTED", "confidence": 0.9}],
    )
    run(agent, phase1_report(path))

    verifier = next(p for s, p in agent.prompts if p.get("role") == "verifier")
    context = verifier["source_context"]
    assert context["available"] is True, context.get("error")
    assert "subprocess" in context["snippet"]
    # The label-hiding rewrite of the path must survive into the packet.
    assert str(path) not in json.dumps(verifier)


def test_agents_announce_their_sample_to_the_thinking_log(tmp_path):
    """Both roles report the real path, whatever the packet shows the model."""
    from agents import thinking_log

    directory = tmp_path / "bad"
    directory.mkdir()
    path = directory / "sample.py"
    path.write_text(VULNERABLE)
    seen: List[Dict[str, Any]] = []

    class ScopedStub(StubAgent):
        async def __call__(self, system: str, packet: Dict[str, Any]):
            seen.append(thinking_log.current_scope())
            return await super().__call__(system, packet)

    agent = ScopedStub(
        {"hypotheses": [{"cwe": "CWE-78", "line": 6, "claim": "x"}]},
        [{"decision": "REJECTED", "confidence": 0.9}],
    )
    run(agent, phase1_report(path))

    assert [s["role"] for s in seen] == ["scanner", "verifier"]
    assert all(s["file"] == str(path) and s["id"] == str(path) for s in seen)


# -- reject by default ---------------------------------------------------

def test_rejected_hypothesis_produces_no_finding(tmp_path):
    path = write(tmp_path, BENIGN)
    agent = StubAgent(
        {"hypotheses": [{"cwe": "CWE-78", "line": 4, "claim": "x"}]},
        [{"decision": "REJECTED", "confidence": 0.95, "explanation": "literal arg"}],
    )
    result = run(agent, phase1_report(path))

    assert result["findings"] == []
    assert result["metadata"]["reported_findings"] == 0
    assert result["decisions"][0]["status"] == "REJECTED"
    assert result["decisions"][0]["rationale"] == "literal arg"


def test_low_confidence_confirmation_is_downgraded(tmp_path):
    path = write(tmp_path, VULNERABLE)
    agent = StubAgent(
        {"hypotheses": [{"cwe": "CWE-78", "line": 6, "claim": "x"}]},
        [{"decision": "CONFIRMED", "confidence": 0.2, "explanation": "maybe",
          "chain_verified": True}],
    )
    result = run(agent, phase1_report(path), min_confidence=0.5)

    assert result["findings"] == []
    assert "below threshold" in result["decisions"][0]["rationale"]


def test_uncertain_is_asked_again_then_resolved(tmp_path):
    """A hedge is re-asked once and, if it persists, becomes a rejection.

    ``UNCERTAIN`` is scored as a miss, so a model that shrugs at code it has
    read pays recall for being cautious rather than wrong. The pipeline asks
    again with the contract spelled out; a hedge with no verified path still
    has nothing to report, and the report must show a verdict, not a shrug.
    """
    path = write(tmp_path, VULNERABLE)
    agent = StubAgent(
        {"hypotheses": [{"cwe": "CWE-78", "line": 6, "claim": "x"}]},
        [{"decision": "UNCERTAIN", "confidence": 0.5}] * 2,
    )
    result = run(agent, phase1_report(path))

    verifier = [p for _, p in agent.prompts if p.get("role") == "verifier"]
    assert len(verifier) == 2, "the hedge must be asked once more"
    assert "correction" in verifier[1], "the repeat question states the contract"
    assert "UNCERTAIN" in verifier[1]["correction"]
    assert result["findings"] == []
    assert result["decisions"][0]["status"] == "REJECTED"
    assert "hedge resolved" in result["decisions"][0]["rationale"]


def test_hedge_over_a_verified_path_is_put_forward(tmp_path):
    """A hedge that reports the path verified is a confirmation the gates judge.

    ``chain_verified: true`` *is* the claim a confirmation makes, so a model
    that hedges while asserting it has not contradicted the packet -- it has
    only declined to press the conclusion. Promotion still leaves the
    deterministic gates (chain in the file, minimum confidence) to decide.
    """
    path = write(tmp_path, VULNERABLE)
    hedge = {"decision": "UNCERTAIN", "confidence": 0.9, "chain_verified": True,
             "explanation": "path from sys.argv to subprocess.run is visible"}
    agent = StubAgent(
        {"hypotheses": [{"cwe": "CWE-78", "line": 6, "claim": "x"}]},
        [dict(hedge), dict(hedge)],
    )
    result = run(agent, phase1_report(path))

    assert result["decisions"][0]["status"] == "CONFIRMED"
    assert "hedge resolved" in result["decisions"][0]["rationale"]
    assert len(result["findings"]) == 1


def test_hedge_retries_zero_asks_once(tmp_path):
    path = write(tmp_path, VULNERABLE)
    agent = StubAgent(
        {"hypotheses": [{"cwe": "CWE-78", "line": 6, "claim": "x"}]},
        [{"decision": "UNCERTAIN", "confidence": 0.5}],
    )
    result = run(agent, phase1_report(path), hedge_retries=0)

    verifier = [p for _, p in agent.prompts if p.get("role") == "verifier"]
    assert len(verifier) == 1
    assert result["findings"] == []
    assert result["decisions"][0]["status"] == "REJECTED"


def test_decisive_verdict_is_never_re_asked(tmp_path):
    """The repeat question costs a model call, so it is spent only on a hedge."""
    path = write(tmp_path, BENIGN)
    agent = StubAgent(
        {"hypotheses": [{"cwe": "CWE-78", "line": 4, "claim": "x"}]},
        [{"decision": "REJECTED", "confidence": 0.95, "explanation": "literal arg"}],
    )
    result = run(agent, phase1_report(path))

    verifier = [p for _, p in agent.prompts if p.get("role") == "verifier"]
    assert len(verifier) == 1
    assert result["decisions"][0]["status"] == "REJECTED"


def test_retry_answer_replaces_the_hedge(tmp_path):
    """When the second answer decides, the report shows that verdict."""
    path = write(tmp_path, VULNERABLE)
    agent = StubAgent(
        {"hypotheses": [{"cwe": "CWE-78", "line": 6, "claim": "x"}]},
        [
            {"decision": "UNCERTAIN", "confidence": 0.4},
            {"decision": "REJECTED", "confidence": 0.9, "explanation": "constant arg"},
        ],
    )
    result = run(agent, phase1_report(path))

    assert result["findings"] == []
    assert result["decisions"][0]["status"] == "REJECTED"
    assert result["decisions"][0]["rationale"] == "constant arg"


def test_unknown_decision_stays_uncertain(tmp_path):
    """A reply with no verdict is not evidence of safety.

    It is asked again like any other hedge, and what it never said cannot be
    resolved into one: an unanswered question stays open in the report.
    """
    path = write(tmp_path, VULNERABLE)
    agent = StubAgent(
        {"hypotheses": [{"cwe": "CWE-78", "line": 6, "claim": "x"}]},
        [{"decision": "MAYBE", "confidence": 0.9}] * 2,
    )
    result = run(agent, phase1_report(path))

    verifier = [p for _, p in agent.prompts if p.get("role") == "verifier"]
    assert len(verifier) == 2
    assert result["findings"] == []
    assert result["decisions"][0]["status"] == "UNCERTAIN"


# -- false alarm reduction ----------------------------------------------

def test_scanner_over_generation_is_absorbed_by_the_verifier(tmp_path):
    """Six weak hypotheses, one real path: only the real one is reported."""
    path = write(tmp_path, VULNERABLE)
    agent = StubAgent(
        {
            "hypotheses": [
                {"cwe": "CWE-78", "line": 6, "claim": "real path"},
                {"cwe": "CWE-89", "line": 1, "claim": "weak 1"},
                {"cwe": "CWE-502", "line": 2, "claim": "weak 2"},
                {"cwe": "CWE-22", "line": 3, "claim": "weak 3"},
                {"cwe": "CWE-94", "line": 4, "claim": "weak 4"},
                {"cwe": "CWE-120", "line": 5, "claim": "weak 5"},
            ]
        },
        [{"decision": "REJECTED", "confidence": 0.9, "explanation": "benign"}],
    )
    result = run(agent, phase1_report(path))

    assert result["metadata"]["hypotheses_proposed"] == 6
    assert len(result["decisions"]) == 6
    assert result["findings"] == []
    assert result["metadata"]["decision_counts"]["REJECTED"] == 6


# -- robustness ----------------------------------------------------------

def test_scanner_failure_is_recorded_not_raised(tmp_path):
    path = write(tmp_path, VULNERABLE)

    async def boom(system: str, packet: Dict[str, Any]) -> Dict[str, Any]:
        raise RuntimeError("provider down")

    import asyncio

    result = asyncio.run(
        MultiAgentPipeline(boom).analyze_file(phase1_report(path))
    )
    assert result["findings"] == []
    assert any("scanner" in e for e in result["errors"])
    assert result["metadata"]["hypotheses_proposed"] == 0


def test_verifier_failure_does_not_lose_the_scan(tmp_path):
    path = write(tmp_path, VULNERABLE)
    calls = {"n": 0}

    async def flaky(system: str, packet: Dict[str, Any]) -> Dict[str, Any]:
        if packet.get("role") == "scanner":
            return {"hypotheses": [{"cwe": "CWE-78", "line": 6, "claim": "x"}]}
        calls["n"] += 1
        raise RuntimeError("timeout")

    import asyncio

    result = asyncio.run(
        MultiAgentPipeline(flaky).analyze_file(phase1_report(path))
    )
    assert result["metadata"]["hypotheses_proposed"] == 1
    assert result["findings"] == []
    assert any("verifier" in e for e in result["errors"])


def test_verifier_receives_no_ground_truth_label(tmp_path):
    """Sanitisation must survive into both agent packets."""
    path = write(
        tmp_path,
        '''
import os
def f(request):
    os.system(request.args.get("CWE78_Command_Injection"))
''',
        "CWE78_Command_Injection__os_system_01_bad.py",
    )
    agent = StubAgent(
        {"hypotheses": [{"cwe": "CWE-78", "line": 3, "claim": "x"}]},
        [{"decision": "REJECTED", "confidence": 0.9}],
    )
    run(agent, phase1_report(path))

    for _, packet in agent.prompts:
        blob = json.dumps(packet)
        assert "CWE78_Command_Injection" not in blob
        assert "_bad" not in blob


# -- chain selection -----------------------------------------------------

def test_chains_near_the_hypothesis_line_are_preferred():
    chains = [
        {"sink_line": 100, "source_line": 90, "chain": "far"},
        {"sink_line": 20, "source_line": 18, "chain": "near"},
    ]
    selected = MultiAgentPipeline._chains_near({"dataflow_chains": chains}, 20)
    assert [c["chain"] for c in selected] == ["near"]


def test_chains_fall_back_to_all_when_none_is_near():
    chains = [{"sink_line": 100, "chain": "far"}]
    selected = MultiAgentPipeline._chains_near({"dataflow_chains": chains}, 5)
    assert selected == chains


def test_no_line_keeps_every_chain():
    chains = [{"sink_line": 100, "chain": "a"}, {"sink_line": 5, "chain": "b"}]
    assert MultiAgentPipeline._chains_near({"dataflow_chains": chains}, None) == chains


# -- catalogue-driven fields --------------------------------------------

def test_cve_and_reference_come_from_the_catalogue_not_the_model(tmp_path):
    """A class with a real-world example resolves to it; a bogus id cannot."""
    path = write(tmp_path, CODE_INJECTION)
    agent = StubAgent(
        {"hypotheses": [{"cwe": "CWE-94", "line": 4, "claim": "x"}]},
        [
            {
                "decision": "CONFIRMED",
                "confidence": 0.9,
                "cwe": ["CWE-94"],
                "explanation": "x",
                "chain_verified": True,
                # A hallucinated identifier in the reply must not reach the report.
                "related_cves": ["CVE-1999-0001"],
                "reference": "https://example.invalid/made-up",
            }
        ],
    )
    from analyzers.catalog import get_catalog

    pipeline = MultiAgentPipeline(agent, catalog=get_catalog())
    import asyncio

    result = asyncio.run(pipeline.analyze_file(phase1_report(path)))
    finding = result["findings"][0]
    assert finding["related_cves"] == ["CVE-2022-22817"]
    assert "CVE-1999-0001" not in json.dumps(finding)
    assert "example.invalid" not in json.dumps(finding)
    expected = get_catalog().report_fields("CWE-94")
    assert set(finding["related_cves"]) <= set(expected["related_cves"])
    assert set(finding["references"]) == set(expected["references"])


def test_location_falls_back_to_the_chain(tmp_path):
    path = write(tmp_path, VULNERABLE)
    agent = StubAgent(
        {"hypotheses": [{"cwe": "CWE-78", "line": 6, "claim": "x"}]},
        [
            {
                "decision": "CONFIRMED",
                "confidence": 0.9,
                "cwe": ["CWE-78"],
                "explanation": "x",
                "chain_verified": True,
            }
        ],
    )
    result = run(agent, phase1_report(path))
    finding = result["findings"][0]
    assert finding["line"] is not None
    assert finding["file"]


# -- the evidence gate ---------------------------------------------------
#
# A prompt instruction is only a request. These tests pin the two conditions the
# proposal makes load bearing, which are therefore enforced in code: a reported
# injection has to have a real source-to-sink path behind it, and a path the
# engine showed to be mitigated is not reported as unmitigated.

NO_CHAIN = '''
import subprocess

def notify():
    subprocess.call("echo done", shell=True)
'''

STRUCTURAL_ONLY = '''
def overflow(a, b):
    return a * b
'''


def confirm(hypothesis):
    return {
        "hypotheses": [hypothesis],
    }


def yes():
    return {
        "decision": "CONFIRMED",
        "confidence": 0.95,
        "chain_verified": True,
        "explanation": "confirmed",
    }


def test_confirmed_without_a_chain_is_rejected(tmp_path):
    """The model cannot describe a path that is not in the file."""
    path = write(tmp_path, NO_CHAIN)
    agent = StubAgent(
        confirm({"cwe": "CWE-78", "line": 4, "claim": "x"}), [yes()]
    )
    result = run(agent, phase1_report(path))

    assert result["findings"] == []
    assert result["metadata"]["reported_findings"] == 0
    assert "no source-to-sink path" in result["decisions"][0]["rationale"]


def test_confirmed_heap_overflow_without_a_chain_is_rejected(tmp_path):
    """CWE-122 names the same overflow-write shape the engine files as
    CWE-120, so it is held to the chain gate: a CONFIRMED heap overflow
    with no source-to-sink path in the file must not be reported."""
    path = write(
        tmp_path,
        '#include <string.h>\n'
        'void greet(void) {\n'
        '    char buf[16];\n'
        '    strcpy(buf, "hello");\n'
        '}\n',
        "ovf.c",
    )
    agent = StubAgent(
        confirm({"cwe": "CWE-122", "line": 4, "claim": "x"}), [yes()]
    )
    result = run(agent, phase1_report(path))

    assert result["findings"] == []
    assert "no source-to-sink path" in result["decisions"][0]["rationale"]


def test_chain_gate_is_the_default_and_can_be_ablated(tmp_path):
    path = write(tmp_path, NO_CHAIN)
    agent = StubAgent(
        confirm({"cwe": "CWE-78", "line": 4, "claim": "x"}), [yes()]
    )
    assert run(agent, phase1_report(path))["findings"] == []

    agent = StubAgent(confirm({"cwe": "CWE-78", "line": 4, "claim": "x"}), [yes()])
    ablated = run(agent, phase1_report(path), require_chain_evidence=False)
    assert len(ablated["findings"]) == 1


def test_structural_class_is_exempt_from_the_chain_gate(tmp_path):
    """An integer overflow is not a data flow, so no chain is not evidence."""
    path = write(tmp_path, STRUCTURAL_ONLY, "ovf.c")
    agent = StubAgent(confirm({"cwe": "CWE-190", "line": 3, "claim": "x"}), [yes()])
    result = run(agent, phase1_report(path))

    assert len(result["findings"]) == 1
    assert result["findings"][0]["cwe"] == "CWE-190"


def test_taint_modelled_covers_the_injection_classes():
    from analyzers.taint import TAINT_MODELLED_CWES, taint_modelled

    assert {"CWE-78", "CWE-94", "CWE-89", "CWE-502", "CWE-22", "CWE-1336"} <= (
        TAINT_MODELLED_CWES
    )
    assert taint_modelled("cwe-78") is True
    assert taint_modelled("CWE-190") is False
    assert taint_modelled("") is False


def test_taint_modelled_covers_the_buffer_overflow_family():
    """Benchmarks label heap overflows CWE-122 while the engine files chains
    under CWE-120; without the alias the chain gate would exempt the
    proposal's flagship C class. Over-reads stay exempt: the engine tracks
    writes to dangerous sinks, not out-of-bounds reads."""
    from analyzers.taint import taint_modelled

    for cwe in ("CWE-122", "CWE-121", "CWE-119", "CWE-787", "CWE-788",
                "CWE-123", "CWE-124", "CWE-131", "cwe-122"):
        assert taint_modelled(cwe) is True, cwe
    for cwe in ("CWE-190", "CWE-191", "CWE-125", "CWE-126", "CWE-127", ""):
        assert taint_modelled(cwe) is False, cwe


def test_confirmation_without_chain_verified_is_rejected(tmp_path):
    """A CONFIRMED verdict that denies its own chain is self-contradictory.

    This is a separate check from the chain gate above: the file here really
    does contain a source-to-sink path, so the deterministic engine has
    nothing to object to. What rejects the finding is the verifier disagreeing
    with itself.
    """
    path = write(tmp_path, VULNERABLE)
    contradictory = {
        "decision": "CONFIRMED",
        "confidence": 0.99,
        "cwe": ["CWE-78"],
        "chain_verified": False,
        "explanation": "confirmed anyway",
    }
    agent = StubAgent(
        confirm({"cwe": "CWE-78", "line": 6, "claim": "x"}), [contradictory]
    )
    result = run(agent, phase1_report(path))

    assert result["findings"] == []
    assert "chain_verified is false" in result["decisions"][0]["rationale"]


def test_chain_verified_is_required_even_with_the_gate_ablated(tmp_path):
    """Ablating the engine check does not license a contradictory verdict."""
    path = write(tmp_path, VULNERABLE)
    contradictory = {
        "decision": "CONFIRMED",
        "confidence": 0.99,
        "cwe": ["CWE-78"],
        "chain_verified": False,
        "explanation": "confirmed anyway",
    }
    agent = StubAgent(
        confirm({"cwe": "CWE-78", "line": 6, "claim": "x"}), [contradictory]
    )
    result = run(agent, phase1_report(path), require_chain_evidence=False)

    assert result["findings"] == []


MITIGATED = '''
import subprocess

def backup(name):
    subprocess.Popen(["pg_dump", name], shell=False)
'''


def test_mitigated_path_is_rejected_when_configured(tmp_path):
    path = write(tmp_path, MITIGATED)
    agent = StubAgent(confirm({"cwe": "CWE-78", "line": 4, "claim": "x"}), [yes()])
    result = run(agent, phase1_report(path), reject_mitigated=True)

    assert result["findings"] == []
    assert "already mitigated" in result["decisions"][0]["rationale"]
    assert "argument-list" in result["decisions"][0]["rationale"]


def test_mitigated_path_is_reported_by_default(tmp_path):
    """The gate is off unless asked for: the verifier may have a reason."""
    path = write(tmp_path, MITIGATED)
    agent = StubAgent(confirm({"cwe": "CWE-78", "line": 4, "claim": "x"}), [yes()])
    assert len(run(agent, phase1_report(path))["findings"]) == 1


# -- evidence the verifier is actually shown -----------------------------

def test_verifier_receives_nearby_static_tool_findings(tmp_path):
    path = write(tmp_path, VULNERABLE)
    report = phase1_report(path)
    report["findings"] = [
        {"rule_id": "B602", "line": 6, "issue_text": "subprocess call with shell=True"},
        {"rule_id": "B404", "line": 900, "issue_text": "import subprocess"},
    ]
    agent = StubAgent(confirm({"cwe": "CWE-78", "line": 6, "claim": "x"}), [yes()])
    run(agent, report)

    packet = next(p for s, p in agent.prompts if p.get("role") == "verifier")
    assert [f["rule_id"] for f in packet["static_tool_findings"]] == ["B602"]


def test_tool_findings_fall_back_to_all_when_none_is_near(tmp_path):
    path = write(tmp_path, VULNERABLE)
    report = phase1_report(path)
    report["findings"] = [
        {"rule_id": "B602", "line": 6, "issue_text": "x"},
        {"rule_id": "B404", "line": 900, "issue_text": "y"},
    ]
    agent = StubAgent(confirm({"cwe": "CWE-78", "line": 50, "claim": "x"}), [yes()])
    run(agent, report)

    packet = next(p for s, p in agent.prompts if p.get("role") == "verifier")
    assert len(packet["static_tool_findings"]) == 2


def test_verifier_gets_no_scanner_reasoning(tmp_path):
    """Showing the verifier the argument for the hypothesis anchors it on it."""
    path = write(tmp_path, VULNERABLE)
    agent = StubAgent(
        {
            "hypotheses": [
                {
                    "cwe": "CWE-78",
                    "line": 6,
                    "claim": "x",
                    "confidence": 0.99,
                    "reasoning": "I am certain this is exploitable",
                }
            ]
        },
        [yes()],
    )
    run(agent, phase1_report(path))

    packet = next(p for s, p in agent.prompts if p.get("role") == "verifier")
    assert "reasoning" not in packet["hypothesis"]
    assert "certain" not in json.dumps(packet)


def test_hypothesis_budget_is_enforced(tmp_path):
    """The budget bounds the raw proposal count, before claims are grouped.

    The twenty proposals here name twenty different CWEs, so the five that
    survive the budget are five claims and five verifier calls: that is what
    the budget promises to bound. Twenty restatements of one claim would
    collapse to a single call instead -- see
    ``test_a_repeated_claim_is_verified_once`` -- which is a saving, not a
    loss, and is not what this test is about.
    """
    path = write(tmp_path, VULNERABLE)
    cwes = [
        "CWE-78", "CWE-89", "CWE-22", "CWE-502", "CWE-94",
        "CWE-79", "CWE-90", "CWE-113", "CWE-116", "CWE-176",
        "CWE-250", "CWE-259", "CWE-306", "CWE-319", "CWE-352",
        "CWE-362", "CWE-494", "CWE-601", "CWE-611", "CWE-759",
    ]
    agent = StubAgent(
        {
            "hypotheses": [
                {"cwe": cwe, "line": 6, "claim": f"h{i}"}
                for i, cwe in enumerate(cwes)
            ]
        },
        [yes()],
    )
    result = run(agent, phase1_report(path), max_hypotheses=5, concurrency=2)

    assert result["metadata"]["hypotheses_proposed"] == 20
    assert result["metadata"]["hypotheses_truncated"] is True
    verifier_calls = [p for s, p in agent.prompts if p.get("role") == "verifier"]
    assert len(verifier_calls) == 5, "the budget must bound the verifier work"


# -- claim grouping -------------------------------------------------------


def test_a_repeated_claim_is_verified_once(tmp_path):
    """Three restatements of CWE-78 at the same sink are one claim.

    The scanner restating a vulnerability it already proposed is the single
    largest source of duplicated report entries in the LLM runs: nine lines
    pointed at nine times became nine CONFIRMED decisions and nine findings,
    eight of them false positives against a matcher that had already matched
    the file. One call, one entry.
    """
    path = write(tmp_path, VULNERABLE)
    agent = StubAgent(
        {
            "hypotheses": [
                {"cwe": "CWE-78", "line": 6, "claim": "h0"},
                {"cwe": "CWE-78", "line": 6, "claim": "h1"},
                {"cwe": "CWE-78", "line": 7, "claim": "h2"},
            ]
        },
        [yes()],
    )
    result = run(agent, phase1_report(path))

    verifier_calls = [p for s, p in agent.prompts if p.get("role") == "verifier"]
    assert len(verifier_calls) == 1, "one claim, one verifier pass"
    assert result["metadata"]["hypotheses_proposed"] == 3
    assert result["metadata"]["claims"] == 1
    assert result["metadata"]["claims_merged"] == 2
    assert len(result["decisions"]) == 1
    assert len(result["findings"]) == 1
    assert result["decisions"][0]["status"] == "CONFIRMED"
    assert result["decisions"][0]["line"] == 6


def test_a_claim_is_verified_until_it_confirms(tmp_path):
    """Sites are tried in the scanner's order and stop at the first CONFIRMED.

    Stopping is what keeps a repeated claim from buying a report entry per
    restatement; trying the next site when a site is rejected is what keeps a
    claim alive when the first line the scanner pointed at was wrong.
    """
    path = write(tmp_path, VULNERABLE)
    agent = StubAgent(
        {
            "hypotheses": [
                {"cwe": "CWE-78", "line": 6, "claim": "first site"},
                {"cwe": "CWE-78", "line": 40, "claim": "second site"},
            ]
        },
        [
            {"decision": "REJECTED", "confidence": 0.9, "explanation": "no path"},
            yes(),
        ],
    )
    result = run(agent, phase1_report(path))

    verifier_calls = [p for s, p in agent.prompts if p.get("role") == "verifier"]
    assert len(verifier_calls) == 2, "the rejected site does not end the claim"
    assert [d["status"] for d in result["decisions"]] == ["REJECTED", "CONFIRMED"]
    assert len(result["findings"]) == 1


def test_confirmed_findings_of_one_family_merge(tmp_path):
    """CWE-120 and CWE-125 are one claim to a reader and to the matcher.

    Two distinct claims that the verifier confirmed, naming an overflow and an
    over-read of the same sink: two report entries, two predictions, and two
    chances to be scored against a ground truth that can only be matched once
    per file. The union of the CWEs keeps recall -- every CWE either entry
    carried is still stated -- while the report says it once.
    """
    path = write(tmp_path, VULNERABLE)
    agent = StubAgent(
        {
            "hypotheses": [
                {"cwe": "CWE-120", "line": 6, "claim": "overflow"},
                {"cwe": "CWE-125", "line": 6, "claim": "over-read"},
            ]
        },
        [yes(), yes()],
    )
    result = run(agent, phase1_report(path))

    assert len(result["findings"]) == 1
    confirmed = [d for d in result["decisions"] if d["status"] == "CONFIRMED"]
    assert len(confirmed) == 1
    assert confirmed[0]["cwe"] == ["CWE-120", "CWE-125"]
    assert confirmed[0]["line"] == 6
    merges = result["metadata"]["claim_merges"]
    assert [m["group_id"] for m in merges] == ["H2"]
    assert merges[0]["merged_into"] == "H1"


def test_merge_is_off_when_configured_off(tmp_path):
    """The ablation switch: claims and merges can both be turned back off."""
    path = write(tmp_path, VULNERABLE)
    agent = StubAgent(
        {
            "hypotheses": [
                {"cwe": "CWE-78", "line": 6, "claim": "h0"},
                {"cwe": "CWE-78", "line": 6, "claim": "h1"},
            ]
        },
        [yes(), yes()],
    )
    result = run(agent, phase1_report(path), merge_claims=False, merge_findings=False)

    verifier_calls = [p for s, p in agent.prompts if p.get("role") == "verifier"]
    assert len(verifier_calls) == 2
    assert len(result["findings"]) == 2
    assert "claim_merges" not in result["metadata"]


def test_scanner_failure_falls_back_to_tool_findings(tmp_path):
    """A dropped Scanner call must not blank a report the tools had filled.

    The fallback hands the tool findings to the verifier as hypotheses, so the
    sample still costs a verifier pass rather than being scored as an error
    with no predictions at all.
    """
    path = write(tmp_path, VULNERABLE)
    report = phase1_report(path)
    report["findings"] = [
        {"cwe": "CWE-78", "line": 6, "message": "shell=True", "rule_id": "B602"}
    ]

    class FailingScanner(StubAgent):
        async def __call__(self, system, packet):
            if packet.get("role") == "scanner":
                self.prompts.append((system, packet))
                raise RuntimeError("scanner unavailable")
            return await super().__call__(system, packet)

    agent = FailingScanner({}, [yes()])
    result = run(agent, report)

    assert result["metadata"]["scanner_fallback"] is True
    assert result["metadata"]["hypotheses_proposed"] == 1
    verifier_calls = [p for s, p in agent.prompts if p.get("role") == "verifier"]
    assert len(verifier_calls) == 1
    assert verifier_calls[0]["hypothesis"]["cwe"] == "CWE-78"
    assert len(result["findings"]) == 1
    assert any("scanner" in error for error in result["errors"])



# -- the phase 2 runner --------------------------------------------------

def _runner():
    """Import ``scripts/run_phase2.py``, which is a script rather than a module."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "run_phase2", Path(__file__).resolve().parent.parent / "scripts" / "run_phase2.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_runner_reads_reports_from_a_file_and_a_directory(tmp_path):
    runner = _runner()
    first = write(tmp_path, VULNERABLE, "a.py")
    reports = [
        {"source": str(first), "language": "python", "findings": []},
        {"source": "other.py", "language": "python", "findings": []},
    ]
    (tmp_path / "one.json").write_text(json.dumps(reports[0]))
    (tmp_path / "two.jsonl").write_text(json.dumps(reports[1]) + "\n")

    assert len(runner.iter_reports([tmp_path / "one.json"])) == 1
    assert len(runner.iter_reports([tmp_path / "two.jsonl"])) == 1
    assert len(runner.iter_reports([tmp_path])) == 2


def test_runner_skips_a_malformed_line_without_losing_the_rest(tmp_path):
    runner = _runner()
    good = {"source": "a.py", "language": "python", "findings": []}
    (tmp_path / "reports.jsonl").write_text(
        json.dumps(good) + "\nnot json\n" + json.dumps(good) + "\n"
    )
    assert len(runner.iter_reports([tmp_path / "reports.jsonl"])) == 2


def test_runner_end_to_end_with_a_stub_agent(tmp_path, monkeypatch):
    """The CLI, the config mapping and the summary are all exercised."""
    runner = _runner()
    path = write(tmp_path, VULNERABLE)
    report = phase1_report(path)
    report["findings"] = [{"rule_id": "B602", "line": 6, "issue_text": "shell=True"}]
    (tmp_path / "report.json").write_text(json.dumps(report, default=str))

    agent = StubAgent(
        confirm({"cwe": "CWE-78", "line": 6, "claim": "x"}), [yes()]
    )
    captured = {}

    def fake_build_pipeline(config=None, **kwargs):
        captured["config"] = config
        return MultiAgentPipeline(agent, config=config)

    monkeypatch.setattr(runner, "build_pipeline", fake_build_pipeline)
    out = tmp_path / "phase2.json"
    code = runner.main([str(tmp_path / "report.json"), "--out", str(out)])

    assert code == 0
    payload = json.loads(out.read_text())
    assert payload["summary"]["architecture"] == "multi_agent"
    assert payload["summary"]["findings"] == 1
    assert payload["summary"]["decisions"]["CONFIRMED"] == 1
    assert captured["config"].include_taint is True
    assert captured["config"].require_chain_evidence is True


def test_runner_records_a_pipeline_failure_as_an_error(tmp_path, monkeypatch):
    runner = _runner()
    path = write(tmp_path, VULNERABLE)
    report = phase1_report(path)
    (tmp_path / "report.json").write_text(json.dumps(report, default=str))

    async def boom(*args, **kwargs):
        raise RuntimeError("endpoint down")

    monkeypatch.setattr(
        runner, "build_pipeline",
        lambda config=None, **kwargs: MultiAgentPipeline(boom, config=config),
    )
    out = tmp_path / "phase2.json"
    assert runner.main([str(tmp_path / "report.json"), "--out", str(out)]) == 0

    payload = json.loads(out.read_text())
    assert payload["summary"]["errors"] == 1
    assert payload["summary"]["findings"] == 0
