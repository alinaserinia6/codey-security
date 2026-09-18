from __future__ import annotations
import asyncio
from .dataset import GroundTruthDataset
from .extract_predictions import predictions_from_phase1, predictions_from_phase2


def run_phase1_benchmark(dataset: GroundTruthDataset, phase1_pipeline, *, skip_missing=False):
    predictions = []
    reports = []
    for sample in dataset:
        path = dataset.resolve_file(sample)
        if not path.exists():
            if skip_missing:
                reports.append(
                    {"sample_id": sample.sample_id, "skipped": True, "reason": "missing file"}
                )
                continue
            raise FileNotFoundError(path)
        report = phase1_pipeline.analyze_file(path)
        reports.append({"sample_id": sample.sample_id, "report": report})
        predictions.extend(predictions_from_phase1(report, sample.sample_id))
    return predictions, reports


async def _run_phase2_benchmark_async(dataset, phase1_pipeline, phase2_pipeline):
    predictions = []
    reports = []
    for sample in dataset:
        path = dataset.resolve_file(sample)
        if not path.exists():
            raise FileNotFoundError(path)
        p1 = phase1_pipeline.analyze_file(path)
        p2 = await phase2_pipeline.analyze_report(p1)
        reports.append({"sample_id": sample.sample_id, "phase1": p1, "phase2": p2})
        predictions.extend(predictions_from_phase2(p2, sample.sample_id))
    return predictions, reports


def run_phase2_benchmark(dataset, phase1_pipeline, phase2_pipeline):
    """Synchronous wrapper around the async Phase 2 benchmark runner.

    The inner coroutine runs on a single event loop so the Phase 2 semaphore
    and HTTP connection pool are reused across samples instead of creating a
    fresh loop per file.
    """
    return asyncio.run(
        _run_phase2_benchmark_async(dataset, phase1_pipeline, phase2_pipeline)
    )
