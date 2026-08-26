from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from analyzers.phase1_pipeline import Phase1Pipeline
from phase2.pipeline import Phase2Config, Phase2Pipeline
from phase3.dataset import GroundTruthDataset
from phase3.evaluator import evaluate
from phase3.report import comparison_rows, save_result
from phase3.runner import run_phase1_benchmark, run_phase2_benchmark


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Phase-3 vulnerability benchmark and metrics.")
    parser.add_argument("dataset", help="Ground-truth JSON manifest")
    parser.add_argument("--mode", choices=["phase1", "phase2"], default="phase1")
    parser.add_argument("--out", default="phase3_result.json")
    parser.add_argument("--line-tolerance", type=int, default=5)
    parser.add_argument("--no-cwe-match", action="store_true")
    parser.add_argument("--provider", default=None)
    args = parser.parse_args()

    dataset = GroundTruthDataset.from_json(args.dataset)
    phase1 = Phase1Pipeline()

    if args.mode == "phase1":
        predictions, reports = run_phase1_benchmark(dataset, phase1)
    else:
        provider = args.provider or os.getenv("PHASE2_LLM_PROVIDER") or os.getenv("DEFAULT_LLM_PROVIDER")
        phase2 = Phase2Pipeline(Phase2Config(provider=provider))
        predictions, reports = run_phase2_benchmark(dataset, phase1, phase2)

    from phase3.matcher import MatchConfig
    result = evaluate(
        args.mode,
        predictions,
        list(dataset),
        match_config=MatchConfig(
            line_tolerance=args.line_tolerance,
            require_cwe_when_available=not args.no_cwe_match,
        ),
    )
    result.metadata["reports"] = reports
    save_result(result, args.out)

    print(json.dumps({"experiment": result.experiment, "metrics": result.metrics.to_dict(), "per_cwe": {k: v.to_dict() for k, v in result.per_cwe.items()}}, indent=2))
    print(f"Report written to {args.out}")


if __name__ == "__main__":
    main()
