#!/usr/bin/env python3
"""Single entry point for Codey-Security.

Usage is intentionally minimal:

    python codey_security.py phase1
    python codey_security.py phase2
    python codey_security.py phase3
    python codey_security.py full

All paths, provider/model settings and scenario references are configured in
`env_config.py` / `.env`.
"""
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import Any

from env_config import Config, ScenarioConfig, get_config


def _write_json(value: Any, path: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(value, indent=2, ensure_ascii=False, default=str) + "\n", encoding="utf-8")
    print(f"Report written to {target}")


def _scenario(config: Config, name: str) -> ScenarioConfig:
    try:
        return config.scenarios[name]
    except KeyError as exc:
        raise RuntimeError(f"Unknown scenario: {name}") from exc


def _make_phase2(config: Config):
    from phase2.pipeline import Phase2Config, Phase2Pipeline

    return Phase2Pipeline(
        Phase2Config(
            provider="deepseek",
            temperature=config.temperature,
            max_tokens=config.max_tokens,
            max_groups=config.max_groups,
            concurrency=config.concurrency,
            context_radius=config.context_radius,
        )
    )


def run_phase1(config: Config) -> dict[str, Any]:
    from analyzers.phase1_pipeline import Phase1Pipeline

    scenario = _scenario(config, "phase1")
    if not scenario.source:
        raise ValueError("phase1 scenario requires source")

    source = Path(scenario.source)
    if not source.exists():
        raise FileNotFoundError(f"Phase 1 source does not exist: {source}")

    report = Phase1Pipeline().analyze_path(str(source))
    _write_json(report, scenario.output)
    return report


def run_phase2(config: Config) -> dict[str, Any]:
    from analyzers.phase1_pipeline import Phase1Pipeline

    scenario = _scenario(config, "phase2")
    if not scenario.source:
        raise ValueError("phase2 scenario requires source")

    source = Path(scenario.source)
    if not source.exists():
        raise FileNotFoundError(f"Phase 2 source does not exist: {source}")

    phase1 = Phase1Pipeline().analyze_path(str(source))
    phase2 = _make_phase2(config)
    result = asyncio.run(phase2.analyze_report(phase1))
    _write_json(result, scenario.output)
    return result


def run_phase3(config: Config) -> dict[str, Any]:
    from analyzers.phase1_pipeline import Phase1Pipeline
    from phase3.dataset import GroundTruthDataset
    from phase3.evaluator import evaluate
    from phase3.matcher import MatchConfig
    from phase3.report import save_result
    from phase3.runner import run_phase1_benchmark, run_phase2_benchmark

    scenario = _scenario(config, "phase3")
    if not scenario.dataset:
        raise ValueError("phase3 scenario requires dataset")
    dataset_path = Path(scenario.dataset)
    if not dataset_path.exists():
        raise FileNotFoundError(f"Phase 3 dataset does not exist: {dataset_path}")
    if scenario.mode not in {"phase1", "phase2"}:
        raise ValueError("SCENARIO_PHASE3_MODE must be 'phase1' or 'phase2'")

    dataset = GroundTruthDataset.from_json(str(dataset_path))
    phase1 = Phase1Pipeline()

    if scenario.mode == "phase1":
        predictions, reports = run_phase1_benchmark(
            dataset, phase1, skip_missing=scenario.skip_missing
        )
    else:
        phase2 = _make_phase2(config)
        predictions, reports = run_phase2_benchmark(dataset, phase1, phase2)

    result = evaluate(
        scenario.mode,
        predictions,
        list(dataset),
        match_config=MatchConfig(
            line_tolerance=config.line_tolerance,
            require_cwe_when_available=scenario.require_cwe_match,
        ),
    )
    result.metadata["reports"] = reports
    save_result(result, scenario.output)
    print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False, default=str))
    print(f"Report written to {scenario.output}")
    return result.to_dict()


def run_full(config: Config) -> dict[str, Any]:
    from analyzers.phase1_pipeline import Phase1Pipeline

    scenario = _scenario(config, "full")
    if not scenario.source:
        raise ValueError("full scenario requires source")

    source = Path(scenario.source)
    if not source.exists():
        raise FileNotFoundError(f"Full-pipeline source does not exist: {source}")

    print("[1/3] Running Phase 1...")
    phase1 = Phase1Pipeline().analyze_path(str(source))
    _write_json(phase1, scenario.phase1_output or "results/phase1_report.json")

    print("[2/3] Running Phase 2...")
    phase2_pipeline = _make_phase2(config)
    phase2 = asyncio.run(phase2_pipeline.analyze_report(phase1))
    _write_json(phase2, scenario.phase2_output or "results/phase2_report.json")

    if not scenario.dataset:
        print("[3/3] Phase 3 skipped: full scenario has no dataset reference.")
        return {"phase1": phase1, "phase2": phase2}

    print("[3/3] Running Phase 3 evaluation...")
    # Reuse the Phase 3 benchmark machinery. The configured dataset is the
    # authoritative reference; no runtime CLI options are needed.
    from phase3.dataset import GroundTruthDataset
    from phase3.evaluator import evaluate
    from phase3.matcher import MatchConfig
    from phase3.report import save_result
    from phase3.runner import run_phase1_benchmark, run_phase2_benchmark

    dataset = GroundTruthDataset.from_json(str(Path(scenario.dataset)))
    phase1_pipeline = Phase1Pipeline()
    if scenario.mode == "phase1":
        predictions, reports = run_phase1_benchmark(dataset, phase1_pipeline)
    elif scenario.mode == "phase2":
        predictions, reports = run_phase2_benchmark(dataset, phase1_pipeline, phase2_pipeline)
    else:
        raise ValueError("SCENARIO_FULL_MODE must be 'phase1' or 'phase2'")

    result = evaluate(
        scenario.mode,
        predictions,
        list(dataset),
        match_config=MatchConfig(
            line_tolerance=config.line_tolerance,
            require_cwe_when_available=scenario.require_cwe_match,
        ),
    )
    result.metadata["reports"] = reports
    evaluation_output = scenario.evaluation_output or "results/phase3_result.json"
    save_result(result, evaluation_output)

    return {"phase1": phase1, "phase2": phase2, "phase3": result.to_dict()}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="codey-security",
        description="Codey-Security vulnerability analysis pipeline.",
    )
    parser.add_argument("--version", action="version", version="Codey-Security 0.5.0")
    parser.add_argument(
        "command",
        choices=("phase1", "phase2", "phase3", "full"),
        help="Pipeline stage to execute. All other settings come from env_config.py / .env.",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    config = get_config()

    if args.command == "phase1":
        run_phase1(config)
    elif args.command == "phase2":
        run_phase2(config)
    elif args.command == "phase3":
        run_phase3(config)
    elif args.command == "full":
        run_full(config)


if __name__ == "__main__":
    main()
