#!/usr/bin/env python3
"""Evaluate an LLM-only baseline run against the frozen ground truth.

Reads the JSONL produced by ``scripts/run_llm_only_benchmark.py`` and scores it
with the same matcher used for every other experiment, so the numbers stay
comparable:

    python scripts/evaluate_llm_only.py \
        --dataset datasets/llm_subset_20.json \
        --predictions results/exp_B_llm_only.jsonl \
        --out results/exp_B_llm_only_eval.json

Only ``CONFIRMED`` records become positive predictions; ``REJECTED`` and
``UNCERTAIN`` produce none.  Samples whose record is missing or errored are
reported as failures in the metadata and count as false negatives when the
ground truth is vulnerable.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, List

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from phase3.dataset import GroundTruthDataset  # noqa: E402
from phase3.evaluator import evaluate  # noqa: E402
from phase3.matcher import MatchConfig  # noqa: E402
from analyzers.normalize import safe_cwe_list  # noqa: E402
from phase3.models import Prediction  # noqa: E402
from phase3.report import save_result  # noqa: E402


#: Human-readable descriptions of lines skipped by the last load_records call.
LOAD_WARNINGS: List[str] = []


def load_records(path: Path) -> List[dict]:
    """Read the JSONL, keeping one record per sample.

    An interrupted run appends duplicates when it is resumed, so the newest
    record wins — except that a transport error never clobbers an existing
    successful judgement.

    A corrupt line or a record without a sample_id is skipped with a
    warning: one bad line in a 4000-line file must not discard the other
    3999 judgements. Skipped lines are counted in ``LOAD_WARNINGS``.
    """
    LOAD_WARNINGS.clear()
    by_id: Dict[str, dict] = {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise FileNotFoundError(f"predictions file not readable: {path}: {exc}") from exc
    for lineno, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            LOAD_WARNINGS.append(f"{path}:{lineno}: invalid JSON, skipped ({exc})")
            continue
        if not isinstance(record, dict) or "sample_id" not in record:
            LOAD_WARNINGS.append(f"{path}:{lineno}: record has no sample_id, skipped")
            continue
        sample_id = str(record["sample_id"])
        previous = by_id.get(sample_id)
        if (
            previous is not None
            and previous.get("decision") != "ERROR"
            and record.get("decision") == "ERROR"
        ):
            continue
        by_id[sample_id] = record
    for warning in LOAD_WARNINGS[:10]:
        print(f"warning: {warning}", file=sys.stderr)
    if len(LOAD_WARNINGS) > 10:
        print(f"warning: ... and {len(LOAD_WARNINGS) - 10} more bad lines", file=sys.stderr)
    return list(by_id.values())


def _safe_int(value) -> "int | None":
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _safe_float(value) -> float:
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0


def build_predictions(records: List[dict], experiment: str) -> List[Prediction]:
    predictions: List[Prediction] = []
    for record in records:
        if str(record.get("decision", "")).upper() != "CONFIRMED":
            continue
        predictions.append(
            Prediction(
                sample_id=str(record["sample_id"]),
                file=str(record.get("file") or ""),
                vulnerable=True,
                cwe=safe_cwe_list(record.get("cwe")),
                line=_safe_int(record.get("line")),
                status="CONFIRMED",
                confidence=_safe_float(record.get("confidence")),
                source=experiment,
                raw=record,
            )
        )
    return predictions


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", required=True, help="ground-truth manifest")
    parser.add_argument("--predictions", required=True, help="JSONL from run_llm_only_benchmark.py")
    parser.add_argument("--out", required=True, help="evaluation result JSON")
    parser.add_argument("--experiment", default="llm_only", help="experiment label")
    parser.add_argument("--line-tolerance", type=int, default=5)
    parser.add_argument("--no-cwe-match", action="store_true")
    parser.add_argument("--model", default=None, help="model id used for the run")
    args = parser.parse_args()

    dataset = GroundTruthDataset.from_json(args.dataset)
    records = load_records(Path(args.predictions))
    predictions = build_predictions(records, args.experiment)

    recorded_models = sorted({str(r["model"]) for r in records if r.get("model")})
    recorded_urls = sorted({str(r["base_url"]) for r in records if r.get("base_url")})
    if not args.model:
        # Provenance must come from the run itself when the runner recorded
        # it, so the evaluation cannot claim a model the run never used.
        if len(recorded_models) == 1:
            args.model = recorded_models[0]
        elif recorded_models:
            args.model = "|".join(recorded_models)
        else:
            from env_config import get_config

            args.model = get_config().llm_model_id

    result = evaluate(
        args.experiment,
        predictions,
        list(dataset),
        match_config=MatchConfig(
            line_tolerance=args.line_tolerance,
            require_cwe_when_available=not args.no_cwe_match,
        ),
    )

    decisions = Counter(str(r.get("decision", "UNKNOWN")).upper() for r in records)
    missing = sorted(
        {s.sample_id for s in dataset} - {str(r["sample_id"]) for r in records}
    )
    errors = [str(r["sample_id"]) for r in records if r.get("error")]
    elapsed = sum(_safe_float(r.get("elapsed")) for r in records)

    result.metadata["provenance"] = {
        "experiment": args.experiment,
        "dataset": str(Path(args.dataset).resolve()),
        "dataset_samples": len(dataset),
        "predictions_file": str(Path(args.predictions).resolve()),
        "model": args.model,
        "models_in_file": recorded_models,
        "base_url": recorded_urls[0] if len(recorded_urls) == 1 else recorded_urls,
        "line_tolerance": args.line_tolerance,
        "require_cwe_match": not args.no_cwe_match,
        "record_count": len(records),
        "skipped_bad_lines": len(LOAD_WARNINGS),
        "decision_counts": dict(decisions),
        "positive_predictions": len(predictions),
        "missing_samples": len(missing),
        "missing_sample_ids": missing[:50],
        "error_samples": len(errors),
        "error_sample_ids": errors[:50],
        "summed_request_seconds": round(elapsed, 2),
    }
    save_result(result, args.out)

    metrics = result.metrics.to_dict()
    print(
        json.dumps(
            {
                "experiment": args.experiment,
                "metrics": metrics,
                "decision_counts": dict(decisions),
                "missing_samples": len(missing),
                "error_samples": len(errors),
            },
            indent=2,
        )
    )
    print(f"Result written to {Path(args.out).resolve()}")


if __name__ == "__main__":
    main()
