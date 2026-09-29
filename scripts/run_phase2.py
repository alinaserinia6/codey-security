"""Run Phase 2 over a set of Phase 1 reports.

Two architectures are available and they are selected on the command line
because they are the experimental variable, not an implementation detail:

``--architecture multi_agent`` (default)
    Scanner proposes hypotheses, Verifier confirms them against a source-to-sink
    chain. This is the design in the proposal.

``--architecture single_agent``
    The original one-agent-per-group path, kept so the two can be compared on
    the same inputs and the same prompt budget.

The multi-agent path is also the one that can run on a file with no static tool
hits, because the scanner proposes from the source and the structural index
rather than from a pre-correlated group.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from phase2.client import build_pipeline  # noqa: E402
from phase2.multiagent import MultiAgentConfig  # noqa: E402
from phase2.pipeline import Phase2Config, Phase2Pipeline  # noqa: E402

ARCHITECTURES = ("multi_agent", "single_agent")


def iter_reports(paths: Iterable[Path]) -> List[Dict[str, Any]]:
    """Load Phase 1 reports from JSON files, JSONL files or directories."""
    reports: List[Dict[str, Any]] = []
    files: List[Path] = []
    for path in paths:
        if path.is_dir():
            files.extend(
                sorted(
                    p for p in path.rglob("*")
                    if p.is_file() and p.suffix in (".json", ".jsonl")
                )
            )
        else:
            files.append(path)

    for path in files:
        try:
            raw_text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            print(f"warning: {path} unreadable ({exc}), skipped", file=sys.stderr)
            continue
        if path.suffix == ".jsonl":
            for line_no, line in enumerate(raw_text.splitlines(), 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    reports.append(json.loads(line))
                except json.JSONDecodeError:
                    print(
                        f"warning: {path}:{line_no} is not valid JSON, skipped",
                        file=sys.stderr,
                    )
        else:
            try:
                payload = json.loads(raw_text)
            except json.JSONDecodeError as error:
                print(f"warning: {path} is not valid JSON ({error})", file=sys.stderr)
                continue
            if isinstance(payload, list):
                reports.extend(r for r in payload if isinstance(r, dict))
            elif isinstance(payload, dict):
                # One file per report, or a mapping of name -> report.
                if {"source", "findings"} & set(payload):
                    reports.append(payload)
                else:
                    reports.extend(
                        r for r in payload.values()
                        if isinstance(r, dict) and "source" in r
                    )
    return reports


def _single_agent_client(args: argparse.Namespace) -> Phase2Pipeline:
    return Phase2Pipeline(
        Phase2Config(
            llm_base_url=args.base_url,
            llm_model_id=args.model_id,
            llm_provider_id=args.provider_id,
            llm_mode=args.mode,
            llm_timeout=args.timeout,
            llm_reuse_session=args.reuse_session,
            context_radius=args.context_radius,
            concurrency=args.concurrency,
            include_structural=not args.no_structural,
        )
    )


async def run(args: argparse.Namespace) -> int:
    reports = iter_reports(args.inputs)
    if not reports:
        print("no Phase 1 reports found", file=sys.stderr)
        return 1
    if args.limit:
        reports = reports[: args.limit]
    print(
        f"{len(reports)} report(s), architecture={args.architecture}",
        file=sys.stderr,
    )

    sem = asyncio.Semaphore(max(1, args.file_concurrency))

    if args.architecture == "multi_agent":
        config = MultiAgentConfig(
            context_radius=args.context_radius,
            max_hypotheses=args.max_hypotheses,
            concurrency=args.concurrency,
            include_taint=not args.no_taint,
            include_structural=not args.no_structural,
            include_tools=not args.no_tools,
            min_confidence=args.min_confidence,
            require_chain_evidence=not args.allow_unproven_chains,
            reject_mitigated=args.reject_mitigated,
        )
        pipeline = build_pipeline(
            config=config,
            base_url=args.base_url,
            model_id=args.model_id,
            provider_id=args.provider_id,
            mode=args.mode,
            timeout=args.timeout,
            reuse_session=args.reuse_session,
            separate_sessions=args.separate_sessions,
        )

        async def one(report: Dict[str, Any]) -> Dict[str, Any]:
            async with sem:
                try:
                    return await pipeline.analyze_file(report)
                except Exception as error:  # noqa: BLE001
                    return {
                        "source": report.get("source"),
                        "findings": [],
                        "decisions": [],
                        "errors": [f"{type(error).__name__}: {error}"],
                    }
    else:
        single = _single_agent_client(args)

        async def one(report: Dict[str, Any]) -> Dict[str, Any]:
            async with sem:
                try:
                    return await single.analyze_report(report)
                except Exception as error:  # noqa: BLE001
                    return {
                        "source": report.get("source"),
                        "findings": [],
                        "decisions": [],
                        "errors": [f"{type(error).__name__}: {error}"],
                    }

    results = await asyncio.gather(*[one(r) for r in reports])
    results = [r for r in results if isinstance(r, dict)]

    totals = {"CONFIRMED": 0, "REJECTED": 0, "UNCERTAIN": 0}
    errors = 0
    for result in results:
        errors += len(result.get("errors", []) or [])
        for decision in result.get("decisions", []) or []:
            status = decision.get("status")
            if status in totals:
                totals[status] += 1

    summary = {
        "architecture": args.architecture,
        "reports": len(results),
        "findings": sum(len(r.get("findings", []) or []) for r in results),
        "decisions": totals,
        "errors": errors,
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    if args.out.suffix == ".jsonl":
        with args.out.open("w", encoding="utf-8") as handle:
            for result in results:
                handle.write(json.dumps(result, ensure_ascii=False) + "\n")
    else:
        args.out.write_text(
            json.dumps({"summary": summary, "reports": results},
                       ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    print(json.dumps(summary, indent=2))
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "inputs", nargs="+", type=Path, help="Phase 1 report files or directories",
    )
    parser.add_argument(
        "--out", type=Path, default=REPO_ROOT / "results" / "phase2_report.json",
    )
    parser.add_argument("--architecture", choices=ARCHITECTURES, default="multi_agent")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--base-url", default=None)
    parser.add_argument("--model-id", default=None)
    parser.add_argument("--provider-id", default=None)
    parser.add_argument("--mode", default=None)
    parser.add_argument("--timeout", type=float, default=None)
    parser.add_argument("--reuse-session", action="store_true", default=None)
    parser.add_argument(
        "--separate-sessions",
        action="store_true",
        help="do not let the verifier see the scanner's conversation",
    )
    parser.add_argument("--context-radius", type=int, default=8)
    parser.add_argument("--max-hypotheses", type=int, default=12)
    parser.add_argument(
        "--concurrency", type=int, default=4,
        help="hypothesis verifications in flight for one file",
    )
    parser.add_argument(
        "--file-concurrency", type=int, default=4,
        help="files in flight; the product of the two is the LLM concurrency",
    )
    parser.add_argument("--min-confidence", type=float, default=0.5)
    parser.add_argument("--reject-mitigated", action="store_true")
    parser.add_argument(
        "--allow-unproven-chains",
        action="store_true",
        help="ablation: drop the requirement that a confirmed injection has a chain",
    )
    parser.add_argument("--no-taint", action="store_true")
    parser.add_argument("--no-structural", action="store_true")
    parser.add_argument("--no-tools", action="store_true")
    args = parser.parse_args(argv)
    # Validate numeric knobs up front so a typo fails fast with a clear
    # message instead of a cryptic Semaphore/asyncio error mid-run.
    if args.limit is not None and args.limit < 0:
        parser.error("--limit must be >= 0")
    for name in ("context_radius", "max_hypotheses", "concurrency", "file_concurrency"):
        if getattr(args, name) < 0 or (name != "context_radius" and getattr(args, name) == 0):
            parser.error(f"--{name.replace('_', '-')} must be a positive integer")
    if args.timeout is not None and not args.timeout > 0:
        parser.error("--timeout must be > 0")
    if not 0.0 <= args.min_confidence <= 1.0:
        parser.error("--min-confidence must be in [0, 1]")
    for path in args.inputs:
        if not path.exists():
            parser.error(f"input does not exist: {path}")
    return asyncio.run(run(args))


if __name__ == "__main__":
    raise SystemExit(main())
