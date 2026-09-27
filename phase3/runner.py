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
        except ValueError:
            pass
    return max(1, (os.cpu_count() or 2))


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

    def _analyze_one(item: Tuple[int, Any, Any]):
        idx, sample, path = item
        report = phase1_pipeline.analyze_file(path)
        return idx, sample, report

    with ThreadPoolExecutor(max_workers=n_workers) as pool:
        futures = [pool.submit(_analyze_one, job) for job in jobs]
        for fut in as_completed(futures):
            idx, sample, report = fut.result()
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
# Phase 2 benchmark — async fan-out with a global semaphore
# ---------------------------------------------------------------------------
async def _run_phase2_benchmark_async(
    dataset: GroundTruthDataset,
    phase1_pipeline,
    phase2_pipeline,
    *,
    progress: bool = True,
    workers: Optional[int] = None,
) -> Tuple[List[Any], List[Dict[str, Any]]]:
    samples = list(dataset)
    total = len(samples)
    reporter = ProgressReporter(total, label="phase2") if progress else None

    n_workers = workers or int(os.getenv("PHASE2_CONCURRENCY", "4"))
    sem = asyncio.Semaphore(max(1, n_workers))

    reports_by_index: List[Optional[Dict[str, Any]]] = [None] * total

    async def _process_one(i: int, sample):
        path = dataset.resolve_file(sample)
        if not path.exists():
            raise FileNotFoundError(path)
        # Phase 1 is CPU-bound; run it in a thread so the loop keeps moving.
        p1 = await asyncio.to_thread(phase1_pipeline.analyze_file, path)
        async with sem:
            p2 = await phase2_pipeline.analyze_report(p1)
        reports_by_index[i] = {
            "sample_id": sample.sample_id,
            "phase1": p1,
            "phase2": p2,
        }
        if reporter:
            counts = p2.get("metadata", {}).get("decision_counts", {})
            reporter.step(
                sample.sample_id,
                extra=(
                    f"groups={p2.get('metadata', {}).get('input_group_count', 0)}  "
                    f"C={counts.get('CONFIRMED', 0)} "
                    f"R={counts.get('REJECTED', 0)} "
                    f"U={counts.get('UNCERTAIN', 0)}"
                ),
            )

    await asyncio.gather(
        *(_process_one(i, s) for i, s in enumerate(samples)),
        return_exceptions=False,
    )

    predictions: List[Any] = []
    reports: List[Dict[str, Any]] = []
    for i, sample in enumerate(samples):
        rep = reports_by_index[i]
        if rep is None:
            continue
        reports.append(rep)
        predictions.extend(predictions_from_phase2(rep["phase2"], sample.sample_id))

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
