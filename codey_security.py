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
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

from env_config import Config, ScenarioConfig, get_config

__version__ = "0.5.0"


def _write_json(value: Any, path: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(value, indent=2, ensure_ascii=False, default=str) + "\n",
        encoding="utf-8",
    )
    print(f"Report written to {target}")


def _scenario(config: Config, name: str) -> ScenarioConfig:
    try:
        return config.scenarios[name]
    except KeyError as exc:
        raise RuntimeError(f"Unknown scenario: {name}") from exc


def _make_phase2(config: Config):
    """Build the Phase 2 pipeline selected by ``PHASE2_ARCHITECTURE``.

    ``multi_agent`` is the proposed design, in which a Scanner proposes
    hypotheses and a Verifier judges them against an evidence packet. The
    single-agent pipeline is the same evidence with the two roles merged, so
    setting the architecture is what isolates the contribution of the split.
    """
    architecture = str(config.phase2_architecture or "multi_agent").strip().lower().replace("-", "_")
    if architecture == "multi_agent":
        from phase2.client import build_pipeline
        from phase2.multiagent import MultiAgentConfig

        return build_pipeline(
            config=MultiAgentConfig(
                context_radius=config.phase2_context_radius,
                context_max_lines=config.phase2_context_max_lines,
                # The single-agent budget was a count of groups to review; the
                # multi-agent equivalent is the scanner's hypothesis budget,
                # which bounds the LLM work in the same way.
                max_hypotheses=config.phase2_max_groups,
                concurrency=config.phase2_concurrency,
                include_structural=config.phase2_include_structural,
                include_taint=config.phase2_include_taint,
                require_chain_evidence=config.phase2_require_chain_evidence,
                reject_mitigated=config.phase2_reject_mitigated,
                drop_tool_echoes=config.phase2_drop_tool_echoes,
                min_confidence=config.phase2_min_confidence,
                verifier_owns_class=config.phase2_verifier_owns_class,
                reject_ungrounded_confirmation=(
                    config.phase2_reject_ungrounded_confirmation
                ),
                merge_claims=config.phase2_merge_claims,
                merge_findings=config.phase2_merge_findings,
                claim_site_radius=config.phase2_claim_site_radius,
                hedge_retries=config.phase2_hedge_retries,
                contradiction_retries=config.phase2_contradiction_retries,
            ),
            base_url=config.llm_base_url,
            model_id=config.llm_model_id,
            provider_id=config.llm_provider_id,
            mode=config.llm_mode,
            timeout=config.llm_timeout,
            reuse_session=config.llm_reuse_session,
        )
    if architecture != "single_agent":
        raise ValueError(
            f"PHASE2_ARCHITECTURE must be 'multi_agent' or 'single_agent', "
            f"not {architecture!r}"
        )

    from phase2.pipeline import Phase2Config, Phase2Pipeline

    return Phase2Pipeline(
        Phase2Config(
            llm_base_url=config.llm_base_url,
            llm_model_id=config.llm_model_id,
            llm_provider_id=config.llm_provider_id,
            llm_mode=config.llm_mode,
            llm_timeout=config.llm_timeout,
            llm_reuse_session=config.llm_reuse_session,
            max_groups=config.phase2_max_groups,
            concurrency=config.phase2_concurrency,
            context_radius=config.phase2_context_radius,
            include_structural=config.phase2_include_structural,
        )
    )


def _source_files(pipeline, path: Path) -> List[Path]:
    """Return a sorted list of analyzable source files for `path`.

    When `path` is a file, returns [file]. When it is a directory, delegates
    to the structural analyzer's language-aware discovery.
    """
    if path.is_file():
        return [path]
    discovered = pipeline.structural.analyze_path(path, recursive=True)
    files: List[Path] = []
    for item in discovered:
        if "error" in item:
            continue
        files.append(Path(item["path"]))
    return sorted(files)


def _collect_report_errors(reports: List[Dict[str, Any]]) -> List[tuple]:
    """(sample_id, error) pairs from Phase-3 style report entries.

    Handles both shapes: phase1 entries carry ``report.errors`` (or a
    ``skipped`` reason) and phase2 entries carry ``phase1``/``phase2``
    sub-reports each with their own ``errors`` list.
    """
    pairs: List[tuple] = []
    for entry in reports:
        sample_id = str(entry.get("sample_id", "<unknown>"))
        if entry.get("skipped"):
            pairs.append((sample_id, f"skipped: {entry.get('reason', 'unknown reason')}"))
            continue
        for key in ("report", "phase1", "phase2"):
            sub = entry.get(key)
            if isinstance(sub, dict):
                for err in sub.get("errors", []) or []:
                    pairs.append((sample_id, f"{key}: {err}" if key != "report" else str(err)))
    return pairs


def _print_error_summary(pairs: List[tuple], *, limit: int = 10) -> None:
    """Echo collected errors to the terminal so failures are visible without
    opening the output JSON. A run whose samples all failed used to look
    identical to a clean one on the terminal."""
    if not pairs:
        return
    print(
        f"\n{len(pairs)} error(s) across "
        f"{len({sample for sample, _ in pairs})} sample(s):",
        file=sys.stderr,
    )
    for sample_id, err in pairs[:limit]:
        print(f"  ERROR {sample_id}: {err}", file=sys.stderr)
    if len(pairs) > limit:
        print(f"  ... and {len(pairs) - limit} more (see output JSON)", file=sys.stderr)


def _pipeline_method(architecture: str) -> str:
    """The provenance label for a directory-level Phase 2 report."""
    normalized = str(architecture or "").strip().lower().replace("-", "_")
    if normalized == "multi_agent":
        return "scanner_then_verifier"
    if normalized == "single_agent":
        return "single_security_agent"
    raise ValueError(
        f"PHASE2_ARCHITECTURE must be 'multi_agent' or 'single_agent', "
        f"not {architecture!r}"
    )


def _analyze_file_report(phase1_pipeline, phase2_pipeline, path: Path) -> Dict[str, Any]:
    """Run Phase 1 and Phase 2 for one file, preserving pipeline failures."""
    try:
        phase1 = phase1_pipeline.analyze_file(path)
    except Exception as exc:  # noqa: BLE001 - one bad file must not stop a directory run
        return {
            "source": str(path),
            "language": "unknown",
            "decisions": [],
            "errors": [f"phase1 {type(exc).__name__}: {exc}"],
            "metadata": {"input_group_count": 0},
        }
    # A Phase 1 structural/tool failure is still a report: run Phase 2 over
    # it so the error is preserved downstream instead of aborting the loop.
    try:
        report = phase2_pipeline.analyze_report(phase1)
        if asyncio.iscoroutine(report):
            report = asyncio.run(report)
        return report
    except Exception as exc:  # noqa: BLE001
        return {
            "source": str(path),
            "language": phase1.get("language", "unknown"),
            "decisions": [],
            "errors": [f"{type(exc).__name__}: {exc}"],
            "metadata": {"input_group_count": 0},
        }


def _merge_phase2_reports(
    root: str, reports: List[Dict[str, Any]], *, method: str = "single_security_agent"
) -> Dict[str, Any]:
    """Merge per-file Phase 2 reports into one directory-level report."""
    decisions: List[Dict[str, Any]] = []
    errors: List[str] = []
    file_entries: List[Dict[str, Any]] = []
    for report in reports:
        meta = report.get("metadata") or {}
        file_entries.append(
            {
                "source": report.get("source"),
                "language": report.get("language"),
                "decision_count": len(report.get("decisions", [])),
                "input_group_count": meta.get(
                    "input_group_count", meta.get("input_finding_count", 0)
                ),
            }
        )
        decisions.extend(report.get("decisions", []))
        for err in report.get("errors", []):
            errors.append(f"{report.get('source', '<unknown>')}: {err}")

    counts = {
        status: sum(1 for d in decisions if d.get("status") == status)
        for status in ("CONFIRMED", "REJECTED", "UNCERTAIN")
    }

    return {
        "source": root,
        "language": (
            "mixed"
            if len({e["language"] for e in file_entries}) > 1
            else (file_entries[0]["language"] if file_entries else "unknown")
        ),
        "decisions": decisions,
        "errors": errors,
        "metadata": {
            "file_count": len(file_entries),
            "files": file_entries,
            "decision_counts": counts,
            "agent": "security",
            "method": method,
        },
    }


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


def _ensure_thinking_out(output: str) -> None:
    """Point the model-reasoning trace next to the report it belongs to.

    ``LLM_THINKING_OUT`` is normally set by ``scripts/run_benchmarks.py``; this
    default keeps a direct ``phase2``/``phase3`` run equally auditable instead
    of only printing the reasoning to a terminal nobody keeps.
    """
    if os.environ.get("LLM_THINKING_OUT"):
        return
    path = Path(output)
    os.environ["LLM_THINKING_OUT"] = str(path.with_suffix(".thinking.json"))


def run_phase2(config: Config) -> dict[str, Any]:
    from analyzers.phase1_pipeline import Phase1Pipeline

    scenario = _scenario(config, "phase2")
    if not scenario.source:
        raise ValueError("phase2 scenario requires source")

    source = Path(scenario.source)
    if not source.exists():
        raise FileNotFoundError(f"Phase 2 source does not exist: {source}")

    _ensure_thinking_out(scenario.output)
    phase1_pipeline = Phase1Pipeline()
    phase2_pipeline = _make_phase2(config)

    if source.is_file():
        phase1 = phase1_pipeline.analyze_file(source)
        result = asyncio.run(phase2_pipeline.analyze_report(phase1))
        _write_json(result, scenario.output)
        for entry in result.get("errors", []) or []:
            print(f"ERROR {entry}", file=sys.stderr, flush=True)
        return result

    # Directory branch: iterate every analyzable file and merge.
    files = _source_files(phase1_pipeline, source)
    if not files:
        raise FileNotFoundError(f"No analyzable source files under: {source}")

    print(f"Phase 2: analyzing {len(files)} file(s) under {source}")
    per_file_reports: List[Dict[str, Any]] = []
    for path in files:
        per_file_reports.append(
            _analyze_file_report(phase1_pipeline, phase2_pipeline, path)
        )

    merged = _merge_phase2_reports(
        str(source),
        per_file_reports,
        method=_pipeline_method(config.phase2_architecture),
    )
    _write_json(merged, scenario.output)
    for entry in merged.get("errors", []) or []:
        print(f"ERROR {entry}", file=sys.stderr, flush=True)
    return merged


def _tool_versions() -> Dict[str, str]:
    """Best-effort record of the deterministic analyzers used in a run."""
    import subprocess

    versions: Dict[str, str] = {}
    for name, argv in (
        ("cppcheck", ["cppcheck", "--version"]),
        ("flawfinder", ["flawfinder", "--version"]),
        ("bandit", ["bandit", "--version"]),
    ):
        try:
            out = subprocess.run(
                argv, capture_output=True, text=True, timeout=30, check=False
            )
            first = (out.stdout or out.stderr or "").strip().splitlines()
            versions[name] = first[0].strip() if first else "unknown"
        except (OSError, subprocess.SubprocessError):
            versions[name] = "unavailable"
    return versions


def _sampling_provenance(mode: str) -> Dict[str, Any]:
    """Sampling knobs for the provenance block.

    Recorded only for the modes that actually call a model: writing a
    temperature next to a static-only run would claim an experiment that never
    happened.  The values come from the transport's own resolution so a result
    file cannot drift from what was sent -- this block exists because
    ``temperature`` and ``reasoning_effort`` were sent on every run and written
    into none of them, which makes a non-determinism claim unauditable.
    """
    if mode != "phase2":
        return {"temperature": None, "reasoning_effort": None}
    from agents.openai_compat import sampling_settings

    return dict(sampling_settings())


def _provenance_block(
    scenario: ScenarioConfig,
    dataset_path: Path | str,
    sample_count: int,
    config: Config,
    *,
    elapsed_seconds: float | None = None,
) -> Dict[str, Any]:
    """Everything needed to say which configuration produced a result.

    Shared by ``run_phase3`` and ``run_full`` so the two paths cannot drift
    apart on the fields a reader uses to tell them apart.  ``elapsed_seconds``
    is passed only where it denotes the same quantity: a phase3 result times
    that phase's evaluation, while ``full`` spans Phase 1 + 2 + 3 and would be
    a different number under the same name, so it is omitted rather than
    invented.
    """
    block: Dict[str, Any] = {
        "dataset": str(dataset_path),
        "dataset_samples": sample_count,
        "mode": scenario.mode,
        "label": os.getenv("SCENARIO_PHASE3_LABEL", scenario.mode),
        "model": config.llm_model_id if scenario.mode == "phase2" else None,
        "base_url": config.llm_base_url if scenario.mode == "phase2" else None,
        "include_structural": (
            config.phase2_include_structural if scenario.mode == "phase2" else None
        ),
        "phase2_concurrency": config.phase2_concurrency,
        "phase2_max_groups": config.phase2_max_groups,
        "line_tolerance": config.phase3_line_tolerance,
        "require_cwe_match": scenario.require_cwe_match,
        **_sampling_provenance(scenario.mode),
    }
    if elapsed_seconds is not None:
        block["elapsed_seconds"] = round(elapsed_seconds, 2)
    block["tool_versions"] = _tool_versions()
    block["python_version"] = sys.version.split()[0]
    block["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    return block


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

    started = time.monotonic()
    dataset = GroundTruthDataset.from_json(str(dataset_path))
    phase1 = Phase1Pipeline()

    if scenario.mode == "phase1":
        predictions, reports = run_phase1_benchmark(
            dataset, phase1, skip_missing=scenario.skip_missing
        )
    else:
        _ensure_thinking_out(scenario.output)
        phase2 = _make_phase2(config)
        predictions, reports = run_phase2_benchmark(dataset, phase1, phase2)

    result = evaluate(
        scenario.mode,
        predictions,
        list(dataset),
        match_config=MatchConfig(
            line_tolerance=config.phase3_line_tolerance,
            require_cwe_when_available=scenario.require_cwe_match,
        ),
    )
    result.metadata["reports"] = reports
    result.metadata["provenance"] = _provenance_block(
        scenario,
        dataset_path,
        len(dataset),
        config,
        elapsed_seconds=time.monotonic() - started,
    )
    save_result(result, scenario.output)
    print(f"Report written to {scenario.output}")
    _print_error_summary(_collect_report_errors(reports))
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
    phase1_pipeline = Phase1Pipeline()
    if source.is_file():
        phase1 = phase1_pipeline.analyze_file(source)
    else:
        phase1 = phase1_pipeline.analyze_path(str(source))
    _write_json(phase1, scenario.phase1_output or "results/phase1_report.json")

    print("[2/3] Running Phase 2...")
    _ensure_thinking_out(scenario.phase2_output or "results/phase2_report.json")
    phase2_pipeline = _make_phase2(config)
    if source.is_file():
        phase2 = asyncio.run(phase2_pipeline.analyze_report(phase1))
    else:
        files = _source_files(phase1_pipeline, source)
        if not files:
            raise FileNotFoundError(f"No analyzable source files under: {source}")
        per_file_reports: List[Dict[str, Any]] = []
        for path in files:
            per_file_reports.append(
                _analyze_file_report(phase1_pipeline, phase2_pipeline, path)
            )
        phase2 = _merge_phase2_reports(
            str(source),
            per_file_reports,
            method=_pipeline_method(config.phase2_architecture),
        )
    _write_json(phase2, scenario.phase2_output or "results/phase2_report.json")

    if not scenario.dataset:
        print("[3/3] Phase 3 skipped: full scenario has no dataset reference.")
        return {"phase1": phase1, "phase2": phase2}

    print("[3/3] Running Phase 3 evaluation...")
    from phase3.dataset import GroundTruthDataset
    from phase3.evaluator import evaluate
    from phase3.matcher import MatchConfig
    from phase3.report import save_result
    from phase3.runner import run_phase1_benchmark, run_phase2_benchmark

    dataset = GroundTruthDataset.from_json(str(Path(scenario.dataset)))
    if scenario.mode == "phase1":
        predictions, reports = run_phase1_benchmark(dataset, phase1_pipeline)
    elif scenario.mode == "phase2":
        predictions, reports = run_phase2_benchmark(
            dataset, phase1_pipeline, phase2_pipeline
        )
    else:
        raise ValueError("SCENARIO_FULL_MODE must be 'phase1' or 'phase2'")

    result = evaluate(
        scenario.mode,
        predictions,
        list(dataset),
        match_config=MatchConfig(
            line_tolerance=config.phase3_line_tolerance,
            require_cwe_when_available=scenario.require_cwe_match,
        ),
    )
    result.metadata["reports"] = reports
    # No elapsed_seconds here: this path covers Phase 1 + 2 + 3 in one run, so
    # a field of that name would not mean what it means in a phase3 result.
    # Everything that identifies *what ran* is recorded; the duration is not
    # invented.
    result.metadata["provenance"] = _provenance_block(
        scenario, scenario.dataset, len(dataset), config
    )
    evaluation_output = scenario.evaluation_output or "results/phase3_result.json"
    save_result(result, evaluation_output)
    print(f"Report written to {evaluation_output}")

    return {"phase1": phase1, "phase2": phase2, "phase3": result.to_dict()}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="codey-security",
        description="Codey-Security vulnerability analysis pipeline.",
    )
    parser.add_argument(
        "--version", action="version", version=f"Codey-Security {__version__}"
    )
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
