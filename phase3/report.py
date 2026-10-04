"""Serialisation helpers for evaluation results."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List

from .models import EvaluationResult


def save_result(result: EvaluationResult, path: str | Path) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(result.to_dict(), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def comparison_rows(results: Iterable[EvaluationResult]) -> List[Dict[str, Any]]:
    """Flatten results into one row of scalar metrics per experiment."""
    rows: List[Dict[str, Any]] = []
    for result in results:
        metrics = result.metrics
        sample_level = (result.metadata.get("sample_level") or {}) if result.metadata else {}
        row: Dict[str, Any] = {
            "experiment": result.experiment,
            "TP": metrics.confusion.tp,
            "FP": metrics.confusion.fp,
            "FN": metrics.confusion.fn,
            "TN": metrics.confusion.tn,
            "precision": metrics.precision,
            "recall": metrics.recall,
            "f1": metrics.f1,
            "fpr": metrics.false_positive_rate,
            "accuracy": metrics.accuracy,
        }
        for key in ("benign_flag_rate", "vulnerable_detection_rate"):
            if key in sample_level:
                row[key] = sample_level[key]
        rows.append(row)
    return rows
