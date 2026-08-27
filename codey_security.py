#!/usr/bin/env python3
"""Unified command-line entry point for Codey-Security.

Replaces the old run_pipeline.py, run_phase2.py and run_phase3.py entry points.
Commands:
  phase1      deterministic structural/static analysis
  phase2      Phase 1 + evidence-aware multi-agent verification
  phase3      benchmark/evaluation against a ground-truth manifest
  full        run Phase 1 -> Phase 2 -> optional Phase 3 in one command
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
from typing import Any

from env_config import get_config


def write_json(value: Any, path: str | None) -> None:
    text = json.dumps(value, indent=2, ensure_ascii=False, default=str) + "\n"
    if path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        print(f"Report written to {target}")
    else:
        print(text)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="codey-security",
        description="Structural, static-analysis and multi-agent code vulnerability assessment.",
    )
    parser.add_argument("--version", action="version", version="Codey-Security 0.4.0")

    sub = parser.add_subparsers(dest="command", required=True)

    p1 = sub.add_parser("phase1", help="Run deterministic structural and static analysis.")
    p1.add_argument("path")
    p1.add_argument("--out", default=None)

    p2 = sub.add_parser("phase2", help="Run Phase 1 followed by multi-agent verification.")
    p2.add_argument("path")
    p2.add_argument("--out", default=None)
    p2.add_argument("--provider", choices=["openai", "claude", "gemini", "ollama"], default=None)
    p2.add_argument("--max-groups", type=int, default=None)
    p2.add_argument("--concurrency", type=int, default=None)
    p2.add_argument("--temperature", type=float, default=None)
    p2.add_argument("--max-tokens", type=int, default=None)

    p3 = sub.add_parser("phase3", help="Run a benchmark and calculate evaluation metrics.")
    p3.add_argument("dataset", help="Ground-truth JSON manifest")
    p3.add_argument("--mode", choices=["phase1", "phase2"], default="phase1")
    p3.add_argument("--out", default=None)
    p3.add_argument("--line-tolerance", type=int, default=None)
    p3.add_argument("--no-cwe-match", action="store_true")
    p3.add_argument("--provider", choices=["openai", "claude", "gemini", "ollama"], default=None)
    p3.add_argument("--max-groups", type=int, default=None)
    p3.add_argument("--concurrency", type=int, default=None)
    p3.add_argument("--temperature", type=float, default=None)
    p3.add_argument("--max-tokens", type=int, default=None)
    p3.add_argument("--skip-missing", action="store_true")

    full = sub.add_parser("full", help="Run Phase 1 -> Phase 2, and optionally Phase 3.")
    full.add_argument("path")
    full.add_argument("--phase1-out", default=None)
    full.add_argument("--phase2-out", default=None)
    full.add_argument("--dataset", default=None, help="Optional ground-truth manifest for Phase 3.")
    full.add_argument("--evaluation-out", default=None)
    full.add_argument("--provider", choices=["openai", "claude", "gemini", "ollama"], default=None)
    full.add_argument("--max-groups", type=int, default=None)
    full.add_argument("--concurrency", type=int, default=None)
    full.add_argument("--temperature", type=float, default=None)
    full.add_argument("--max-tokens", type=int, default=None)
    full.add_argument("--line-tolerance", type=int, default=None)
    full.add_argument("--no-cwe-match", action="store_true")

    return parser


def run_phase1(path: str, out: str | None) -> dict[str, Any]:
    from analyzers.phase1_pipeline import Phase1Pipeline

    report = Phase1Pipeline().analyze_path(path)
    write_json(report, out)
    return report


def make_phase2_pipeline(args: argparse.Namespace):
    from phase2.pipeline import Phase2Config, Phase2Pipeline

    cfg = get_config()
    provider = args.provider or cfg.default_llm_provider
    return Phase2Pipeline(
        Phase2Config(
            provider=provider,
            temperature=args.temperature if args.temperature is not None else cfg.temperature,
            max_tokens=args.max_tokens if args.max_tokens is not None else cfg.max_tokens,
            max_groups=args.max_groups if args.max_groups is not None else cfg.max_groups,
            concurrency=args.concurrency if args.concurrency is not None else cfg.concurrency,
            context_radius=cfg.context_radius,
        )
    )


def run_phase2(path: str, out: str | None, args: argparse.Namespace) -> dict[str, Any]:
    from analyzers.phase1_pipeline import Phase1Pipeline

    phase1 = Phase1Pipeline().analyze_path(path)
    phase2 = make_phase2_pipeline(args)
    result = asyncio.run(phase2.analyze_report(phase1))
    write_json(result, out)
    print(json.dumps(result.get("metadata", {}), indent=2, ensure_ascii=False))
    return result


def run_phase3(args: argparse.Namespace) -> dict[str, Any]:
    from analyzers.phase1_pipeline import Phase1Pipeline
    from phase3.dataset import GroundTruthDataset
    from phase3.evaluator import evaluate
    from phase3.report import save_result
    from phase3.runner import run_phase1_benchmark, run_phase2_benchmark
    from phase3.matcher import MatchConfig

    dataset = GroundTruthDataset.from_json(args.dataset)
    phase1 = Phase1Pipeline()

    if args.mode == "phase1":
        predictions, reports = run_phase1_benchmark(dataset, phase1, skip_missing=args.skip_missing)
    else:
        phase2 = make_phase2_pipeline(args)
        predictions, reports = run_phase2_benchmark(dataset, phase1, phase2)

    cfg = get_config()
    result = evaluate(
        args.mode,
        predictions,
        list(dataset),
        match_config=MatchConfig(
            line_tolerance=args.line_tolerance if args.line_tolerance is not None else cfg.line_tolerance,
            require_cwe_when_available=not args.no_cwe_match,
        ),
    )
    result.metadata["reports"] = reports
    out = args.out or cfg.phase3_output
    save_result(result, out)

    summary = {
        "experiment": result.experiment,
        "metrics": result.metrics.to_dict(),
        "per_cwe": {key: value.to_dict() for key, value in result.per_cwe.items()},
    }
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    print(f"Report written to {out}")
    return result.to_dict()


def run_full(args: argparse.Namespace) -> None:
    cfg = get_config()
    source = Path(args.path)

    phase1_out = args.phase1_out or cfg.phase1_output
    phase2_out = args.phase2_out or cfg.phase2_output

    print("[1/3] Running Phase 1...")
    p1 = run_phase1(str(source), phase1_out)

    print("[2/3] Running Phase 2...")
    phase2 = make_phase2_pipeline(args)
    p2 = asyncio.run(phase2.analyze_report(p1))
    write_json(p2, phase2_out)

    if not args.dataset:
        print("[3/3] Phase 3 skipped (no --dataset supplied).")
        return

    print("[3/3] Running Phase 3 evaluation...")
    # Phase 3 needs a benchmark manifest and re-runs the selected benchmark mode.
    eval_args = argparse.Namespace(
        dataset=args.dataset,
        mode="phase2",
        out=args.evaluation_out or cfg.phase3_output,
        line_tolerance=args.line_tolerance,
        no_cwe_match=args.no_cwe_match,
        provider=args.provider,
        max_groups=args.max_groups,
        concurrency=args.concurrency,
        temperature=args.temperature,
        max_tokens=args.max_tokens,
        skip_missing=False,
    )
    run_phase3(eval_args)


def main() -> None:
    args = build_parser().parse_args()
    if args.command == "phase1":
        run_phase1(args.path, args.out)
    elif args.command == "phase2":
        run_phase2(args.path, args.out or get_config().phase2_output, args)
    elif args.command == "phase3":
        run_phase3(args)
    elif args.command == "full":
        run_full(args)
    else:
        raise RuntimeError(f"Unknown command: {args.command}")


if __name__ == "__main__":
    main()
