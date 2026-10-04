"""Re-score a finished run with the *current* deterministic Phase 2 code.

The LLM answers a finished run already wrote down: every scanner reply and
every verifier verdict is in ``<run>.thinking.json``, and every Phase 1 report is
in ``<run>.json``. What can change afterwards is everything the pipeline decides
on its own -- which hypotheses survive as claims, which a gate drops, which
class the report carries, which confirmations fold together. Those are pure
functions of the recorded answers, so they can be replayed offline.

That makes this a harness for the deterministic half of the pipeline:

* it answers "did this change move precision/recall, or did it only move code"
  without paying for another pass over the endpoint, and
* it isolates code regressions from model noise, because the model side is held
  fixed.

It cannot tell you what the new *prompts* would make the model say. The
recorded verdicts are the ones the old prompts produced. That half needs a real
run; see ``scripts/run_benchmarks.py``.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analyzers.catalog import get_catalog  # noqa: E402
from analyzers.taint import taint_chains_for  # noqa: E402
from phase2.models import FinalDecision, ReportFinding, Verification  # noqa: E402
from phase2.multiagent import MultiAgentConfig, MultiAgentPipeline  # noqa: E402
from phase3.dataset import GroundTruthDataset  # noqa: E402
from phase3.evaluator import evaluate  # noqa: E402
from phase3.extract_predictions import predictions_from_phase2  # noqa: E402
from phase3.matcher import MatchConfig  # noqa: E402


def _pipeline(cfg: MultiAgentConfig) -> MultiAgentPipeline:
    """A pipeline with no transport: only its deterministic methods are used."""
    pipe = MultiAgentPipeline.__new__(MultiAgentPipeline)
    pipe.cfg = cfg
    pipe.catalog = get_catalog()
    return pipe


def _calls(entry: Dict[str, Any], role: str) -> List[Dict[str, Any]]:
    return [
        call
        for call in (entry.get("calls") or [])
        if call.get("role") == role and not call.get("error")
    ]


def _errored_calls(entry: Dict[str, Any], role: str) -> int:
    return sum(
        1
        for call in (entry.get("calls") or [])
        if call.get("role") == role and call.get("error")
    )


def _final_verdicts(entry: Dict[str, Any]) -> Dict[str, Verification]:
    """The verdict the live pipeline ended up with, per hypothesis.

    Last answer wins, not first. The Verifier is asked a second time when its
    first answer contradicts itself, and it is the second answer the pipeline
    judged -- so a harness that keeps the first is scoring an answer the run
    threw away. On a recorded C benchmark that was 18 of the hypotheses, and it
    is the whole difference between a replay that reproduces its run (3 false
    positives) and one that does not (17).

    Verdicts whose hypothesis cannot be identified -- which happens when the
    scanner was retried after a failure and produced a second, differently
    numbered reply -- are left out rather than attributed to the wrong claim.
    """
    verdicts: Dict[str, Verification] = {}
    for call in _calls(entry, "verifier"):
        tag = call.get("hypothesis")
        if tag:
            verdicts[tag] = MultiAgentPipeline._parse_verification(
                call.get("answer") or {}
            )
    return verdicts


def replay_file(
    pipe: MultiAgentPipeline,
    report: Dict[str, Any],
    entry: Dict[str, Any],
) -> Dict[str, Any]:
    """Run one file's recorded answers through the current claim/gate logic.

    A verdict is tied to the hypothesis it answered by the id the thinking log
    records for it, so the pairing is exact rather than positional. Every step
    that changes the outcome is delegated to the pipeline's own method -- the
    fallback predicate, the hedge resolution, the gates, the merge -- because a
    harness that reimplements them is a harness that quietly measures a program
    that never ran.
    """
    source = str(report.get("source") or report.get("path") or "")
    metadata: Dict[str, Any] = {"source": source}
    structure = (report.get("metadata") or {}).get("structure") or {}
    chains = taint_chains_for(structure) if structure else []
    engine_silent = not chains

    verdicts = _final_verdicts(entry)
    scanner_failed = _errored_calls(entry, "scanner") > 0
    scanner_calls = _calls(entry, "scanner")

    # When every scanner call failed there is no reply to iterate, so the
    # fallback has to be evaluated on its own -- that is the case the live run
    # recorded as ``scanner_failed``, and skipping it loses the tool findings on
    # exactly the files whose scanner call was the thing that broke.
    replies = [
        MultiAgentPipeline._parse_hypotheses(call.get("answer") or {})
        for call in scanner_calls
    ] or [[]]

    verified: List[Tuple[FinalDecision, Optional[ReportFinding]]] = []
    for reply in replies:
        hypotheses = list(reply)
        proposed = len(hypotheses)

        if pipe.cfg.drop_tool_echoes:
            echoes = pipe._tool_echoes(hypotheses, report)
            if echoes:
                metadata.setdefault("tool_echo_hypotheses", []).extend(
                    {"id": h.id, "cwe": h.cwe, "line": h.line} for h in echoes
                )
                ids = {h.id for h in echoes}
                hypotheses = [h for h in hypotheses if h.id not in ids]

        # The pipeline's own predicate, so a fallback case added there is not
        # silently absent here.
        reason = pipe._fallback_reason(
            not hypotheses,
            scanner_failed,
            proposed,
            report.get("findings") or [],
        )
        if reason:
            hypotheses = pipe._fallback_hypotheses(report)
            if hypotheses:
                metadata["scanner_fallback"] = True
                metadata["scanner_fallback_reason"] = reason
        hypotheses = hypotheses[: max(1, pipe.cfg.max_hypotheses)]

        known = {h.id for h in hypotheses}
        for claim in pipe._claims(hypotheses):
            for site in pipe._sites(claim):
                hypothesis = site[0]
                if hypothesis.id not in known:
                    break
                verification = verdicts.get(hypothesis.id)
                if verification is None:
                    break  # the verifier never got to this site
                # The pipeline resolves a hedge before it gates the answer, so a
                # recorded UNCERTAIN has to be resolved the same way here.
                verification = pipe._resolve_hedge(verification)
                outcome = pipe._decide(
                    hypothesis, verification, chains, engine_silent, source
                )
                if outcome is None:
                    break
                verified.append(outcome)
                if outcome[0].status == "CONFIRMED":
                    break

    if pipe.cfg.merge_findings:
        verified, merges = pipe._merge_findings(verified)
        if merges:
            metadata["claim_merges"] = merges

    return {
        "source": source,
        "language": report.get("language", "unknown"),
        "decisions": [decision.to_dict() for decision, _ in verified],
        "findings": [f.to_dict() for _, f in verified if f is not None],
        "metadata": metadata,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("result", help="results/<run>.json")
    parser.add_argument("thinking", nargs="?", help="results/<run>.thinking.json")
    parser.add_argument("--dataset", help="dataset JSON (defaults to provenance)")
    parser.add_argument("--label", default="replay")
    parser.add_argument("--no-cwe-match", action="store_true")
    parser.add_argument("--keep-tool-echoes", action="store_true")
    parser.add_argument(
        "--require-chain-evidence", dest="require_chain", action="store_true"
    )
    parser.add_argument(
        "--no-require-chain-evidence", dest="require_chain", action="store_false"
    )
    parser.set_defaults(require_chain=True)
    args = parser.parse_args()

    result_path = Path(args.result)
    payload = json.loads(result_path.read_text())
    if args.thinking:
        thinking_path = Path(args.thinking)
    else:
        candidate = result_path.with_name(result_path.stem + ".thinking.json")
        thinking_path = candidate if candidate.exists() else result_path
    thinking = json.loads(thinking_path.read_text()).get("files", {})

    provenance = payload["metadata"]["provenance"]
    dataset_path = args.dataset or provenance["dataset"]
    dataset = GroundTruthDataset.from_json(Path(dataset_path))
    by_sample = {g.sample_id: g for g in dataset.samples}

    cfg = MultiAgentConfig(
        drop_tool_echoes=not args.keep_tool_echoes,
        require_chain_evidence=args.require_chain,
        max_hypotheses=int(provenance.get("phase2_max_groups", 50)),
    )
    pipe = _pipeline(cfg)

    ground_truth = []
    reports = []
    for entry in payload["metadata"]["reports"]:
        report = entry.get("phase1") or {}
        calls = thinking.get(str(report.get("source") or ""))
        sample_id = entry.get("sample_id")
        if not calls or sample_id not in by_sample:
            continue
        replayed = replay_file(pipe, report, calls)
        replayed["sample_id"] = sample_id
        reports.append(replayed)
        ground_truth.append(by_sample[sample_id])

    predictions: List[Any] = []
    for replayed in reports:
        predictions.extend(
            predictions_from_phase2(replayed, replayed["sample_id"])
        )

    out = evaluate(
        args.label,
        predictions,
        ground_truth,
        match_config=MatchConfig(
            line_tolerance=int(provenance.get("line_tolerance", 5)),
            require_cwe_when_available=not args.no_cwe_match,
        ),
    )
    confusion = out.metrics.confusion
    print(f"experiment           : {args.label}")
    print(f"samples scored       : {len(ground_truth)}")
    print(
        f"confusion            : tp={confusion.tp} fp={confusion.fp} "
        f"fn={confusion.fn} tn={confusion.tn}"
    )
    print(f"precision            : {out.metrics.precision:.3f}")
    print(f"recall               : {out.metrics.recall:.3f}")
    print(f"f1                   : {out.metrics.f1:.3f}")
    print(f"findings reported    : {len(predictions)}")
    print(
        "tool echoes dropped  : "
        f"{sum(len(r['metadata'].get('tool_echo_hypotheses', [])) for r in reports)}"
    )
    print(
        "scanner fallbacks    : "
        f"{sum(1 for r in reports if r['metadata'].get('scanner_fallback'))}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())