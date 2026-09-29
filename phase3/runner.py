from __future__ import annotations

import asyncio
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

from .dataset import GroundTruthDataset
from .extract_predictions import predictions_from_phase1, predictions_from_phase2


# ---------------------------------------------------------------------------
# Progress reporting (thread-safe)
# ---------------------------------------------------------------------------
def _human(seconds: float) -> str:
    if seconds != seconds or seconds < 0:
        return "?"
    if seconds < 60:
        return f"{seconds:.1f}s"
    m, s = divmod(int(seconds), 60)
    if m < 60:
        return f"{m}m{s:02d}s"
    h, m = divmod(m, 60)
    return f"{h}h{m:02d}m"


def _truncate(text: str, width: int) -> str:
    text = str(text)
    return text if len(text) <= width else text[: width - 3] + "..."


class ProgressReporter:
    """Thread-safe one-line-per-sample progress on stderr."""

    def __init__(self, total: int, *, label: str = "phase3", stream=None) -> None:
        self.total = total
        self.label = label
        self.stream = stream or sys.stderr
        self.start = time.monotonic()
        self.i = 0
        self._lock = __import__("threading").Lock()

    def step(self, sample_id: str, *, extra: str = "") -> None:
        with self._lock:
            self.i += 1
            elapsed = time.monotonic() - self.start
            rate = self.i / elapsed if elapsed > 0 else 0.0
            pct = 100.0 * self.i / self.total if self.total else 0.0
            eta = (self.total - self.i) / rate if rate > 0 else float("inf")
            eta_str = "?" if eta == float("inf") else _human(eta)
            line = (
                f"[{self.i:>5}/{self.total}] {pct:5.1f}%  "
                f"{_truncate(sample_id, 55):<55}  "
                f"elapsed {_human(elapsed):>7}  eta {eta_str:>7}"
            )
            if extra:
                line += f"  {extra}"
            print(line, file=self.stream, flush=True)


def _default_workers() -> int:
    env = os.getenv("PHASE3_WORKERS")
    if env:
        try:
            n = int(env)
            if n > 0:
                return n
        except (TypeError, ValueError):
            pass
    return max(1, (os.cpu_count() or 2))


def _llm_workers() -> int:
    """Parse PHASE2_CONCURRENCY defensively; fall back to 4 on bad values."""
    try:
        n = int(os.getenv("PHASE2_CONCURRENCY", "4"))
    except (TypeError, ValueError):
        return 4
    return n if n > 0 else 4


# ---------------------------------------------------------------------------
# Phase 1 benchmark — ThreadPoolExecutor
# ---------------------------------------------------------------------------
def run_phase1_benchmark(
    dataset: GroundTruthDataset,
    phase1_pipeline,
    *,
    skip_missing: bool = False,
    progress: bool = True,
    workers: Optional[int] = None,
) -> Tuple[List[Any], List[Dict[str, Any]]]:
    samples = list(dataset)
    total = len(samples)
    reporter = ProgressReporter(total, label="phase1") if progress else None

    # Resolve paths once; drop missing files up front if skip_missing.
    jobs: List[Tuple[int, Any, Any]] = []  # (index, sample, path)
    reports_by_index: List[Optional[Dict[str, Any]]] = [None] * total
    for i, sample in enumerate(samples):
        path = dataset.resolve_file(sample)
        if not path.exists():
            if skip_missing:
                reports_by_index[i] = {
                    "sample_id": sample.sample_id,
                    "skipped": True,
                    "reason": "missing file",
                }
                if reporter:
                    reporter.step(sample.sample_id, extra="skip: missing file")
                continue
            raise FileNotFoundError(path)
        jobs.append((i, sample, path))

    n_workers = workers or _default_workers()
    if n_workers < 1:
        n_workers = 1

    def _analyze_one(item: Tuple[int, Any, Any]):
        idx, sample, path = item
        try:
            report = phase1_pipeline.analyze_file(path)
        except Exception as exc:  # noqa: BLE001 - one bad sample must not stop a benchmark
            report = {
                "source": str(path),
                "language": "unknown",
                "findings": [],
                "errors": [f"{type(exc).__name__}: {exc}"],
                "metadata": {"structure": {}, "analysis_failed": True},
            }
        return idx, sample, report

    with ThreadPoolExecutor(max_workers=n_workers) as pool:
        futures = [pool.submit(_analyze_one, job) for job in jobs]
        for fut in as_completed(futures):
            try:
                idx, sample, report = fut.result()
            except Exception as exc:  # noqa: BLE001 - defensive; _analyze_one already isolates
                continue
            reports_by_index[idx] = {"sample_id": sample.sample_id, "report": report}
            if reporter:
                reporter.step(
                    sample.sample_id,
                    extra=f"findings={len(report.get('findings', []))}",
                )

    # Reassemble in dataset order so the manifest and reports line up.
    predictions: List[Any] = []
    reports: List[Dict[str, Any]] = []
    for i, sample in enumerate(samples):
        rep = reports_by_index[i]
        if rep is None:
            continue
        reports.append(rep)
        if rep.get("skipped"):
            continue
        predictions.extend(predictions_from_phase1(rep["report"], sample.sample_id))

    return predictions, reports


# ---------------------------------------------------------------------------
# Phase 2 benchmark — Phase 1 on a dedicated pool, then async LLM fan-out
# ---------------------------------------------------------------------------
async def _run_phase2_benchmark_async(
    dataset: GroundTruthDataset,
    phase1_pipeline,
    phase2_pipeline,
    *,
    progress: bool = True,
    workers: Optional[int] = None,
) -> Tuple[List[Any], List[Dict[str, Any]]]:
    """Run Phase 1 for every sample, then verify the findings with the agent.

    Phase 1 (external analyzers) and Phase 2 (blocking LLM calls) both need
    worker threads.  Sharing the event loop's default executor makes the LLM
    calls starve the analyzers — or the other way round — so Phase 1 runs on
    its own ThreadPoolExecutor and only the agent work is fanned out with
    asyncio afterwards.
    """
    samples = list(dataset)
    total = len(samples)
    reporter = ProgressReporter(total, label="phase1+2") if progress else None

    n_workers = workers or _default_workers()
    if n_workers < 1:
        n_workers = 1
    loop = asyncio.get_running_loop()
    pool = ThreadPoolExecutor(max_workers=n_workers)

    phase1_by_index: List[Optional[Dict[str, Any]]] = [None] * total

    def _analyze_one(index: int, sample):
        try:
            path = dataset.resolve_file(sample)
        except Exception as exc:  # noqa: BLE001
            return index, {
                "source": getattr(sample, "file", "<unknown>"),
                "language": "unknown",
                "findings": [],
                "errors": [f"unresolvable sample path: {type(exc).__name__}: {exc}"],
                "metadata": {"structure": {}, "analysis_failed": True},
            }
        if not path.exists():
            return index, {
                "source": str(path),
                "language": "unknown",
                "findings": [],
                "errors": [f"missing file: {path}"],
                "metadata": {"structure": {}, "analysis_failed": True},
            }
        try:
            report = phase1_pipeline.analyze_file(path)
        except Exception as exc:  # noqa: BLE001 - one bad sample must not stop a benchmark
            report = {
                "source": str(path),
                "language": "unknown",
                "findings": [],
                "errors": [f"{type(exc).__name__}: {exc}"],
                "metadata": {"structure": {}, "analysis_failed": True},
            }
        return index, report

    try:
        futures = [
            loop.run_in_executor(pool, _analyze_one, i, sample)
            for i, sample in enumerate(samples)
        ]
        for fut in asyncio.as_completed(futures):
            try:
                index, report = await fut
            except Exception as exc:  # noqa: BLE001 - defensive; _analyze_one already isolates
                continue
            phase1_by_index[index] = report
            if reporter:
                reporter.step(
                    samples[index].sample_id,
                    extra=f"findings={len(report.get('findings', []))}",
                )
    finally:
        pool.shutdown(wait=True)

    # --- Phase 2: verify the correlated findings with the Security Agent ---
    llm_workers = _llm_workers()
    sem = asyncio.Semaphore(max(1, llm_workers))
    reporter2 = ProgressReporter(total, label="phase2") if progress else None
    state = {"i": 0, "confirmed": 0, "rejected": 0, "uncertain": 0, "lock": asyncio.Lock()}

    async def _verify_one(index: int, sample, report: Dict[str, Any]) -> Dict[str, Any]:
        async with sem:
            try:
                phase2 = await phase2_pipeline.analyze_report(report)
            except Exception as exc:  # noqa: BLE001 - one LLM failure must not stop a benchmark
                phase2 = {
                    "source": report.get("source", "<unknown>"),
                    "language": report.get("language", "unknown"),
                    "decisions": [],
                    "errors": [f"{type(exc).__name__}: {exc}"],
                    "metadata": {"input_group_count": 0, "analysis_failed": True},
                }
        async with state["lock"]:
            state["i"] += 1
            counts = phase2.get("metadata", {}).get("decision_counts", {})
            state["confirmed"] += counts.get("CONFIRMED", 0)
            state["rejected"] += counts.get("REJECTED", 0)
            state["uncertain"] += counts.get("UNCERTAIN", 0)
            if reporter2:
                reporter2.step(
                    sample.sample_id,
                    extra=(
                        f"groups={phase2.get('metadata', {}).get('input_group_count', 0)}  "
                        f"C={state['confirmed']} R={state['rejected']} U={state['uncertain']}"
                    ),
                )
        return phase2

    phase2_by_index: List[Optional[Dict[str, Any]]] = [None] * total
    pending = [
        _verify_one(i, samples[i], phase1_by_index[i])
        for i in range(total)
        if phase1_by_index[i] is not None
    ]
    if pending:
        results = await asyncio.gather(*pending, return_exceptions=True)
        order = [i for i in range(total) if phase1_by_index[i] is not None]
        for i, phase2 in zip(order, results):
            if isinstance(phase2, BaseException):
                phase2 = {
                    "source": str(phase1_by_index[i].get("source", "<unknown>")),
                    "language": str(phase1_by_index[i].get("language", "unknown")),
                    "decisions": [],
                    "errors": [f"{type(phase2).__name__}: {phase2}"],
                    "metadata": {"input_group_count": 0, "analysis_failed": True},
                }
            phase2_by_index[i] = phase2

    predictions: List[Any] = []
    reports: List[Dict[str, Any]] = []
    for i, sample in enumerate(samples):
        p1, p2 = phase1_by_index[i], phase2_by_index[i]
        if p1 is None or p2 is None:
            continue
        reports.append({"sample_id": sample.sample_id, "phase1": p1, "phase2": p2})
        predictions.extend(predictions_from_phase2(p2, sample.sample_id))

    return predictions, reports


def run_phase2_benchmark(
    dataset: GroundTruthDataset,
    phase1_pipeline,
    phase2_pipeline,
    *,
    progress: bool = True,
    workers: Optional[int] = None,
) -> Tuple[List[Any], List[Dict[str, Any]]]:
    return asyncio.run(
        _run_phase2_benchmark_async(
            dataset,
            phase1_pipeline,
            phase2_pipeline,
            progress=progress,
            workers=workers,
        )
    )
