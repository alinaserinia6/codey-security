from __future__ import annotations
import csv
import json
from pathlib import Path
from typing import Iterable, List


def _validate_result(payload: dict, path: Path) -> None:
    if not isinstance(payload, dict):
        raise ValueError(f"{path}: top-level JSON must be an object")
    if "experiment" not in payload:
        raise ValueError(
            f"{path}: missing 'experiment' key; this does not look like a "
            "Phase-3 result file"
        )
    metrics = payload.get("metrics")
    if not isinstance(metrics, dict):
        raise ValueError(f"{path}: missing or invalid 'metrics' object")
    confusion = metrics.get("confusion")
    if not isinstance(confusion, dict):
        raise ValueError(f"{path}: missing 'metrics.confusion' object")
    for key in ("tp", "fp", "fn", "tn"):
        if key not in confusion:
            raise ValueError(f"{path}: missing 'metrics.confusion.{key}'")


def load_results(paths: Iterable[str | Path]) -> List[dict]:
    results: List[dict] = []
    for p in paths:
        path = Path(p)
        payload = json.loads(path.read_text(encoding="utf-8"))
        _validate_result(payload, path)
        results.append(payload)
    return results


def summary_rows(results: Iterable[dict]) -> List[dict]:
    rows = []
    for r in results:
        m = r["metrics"]
        c = m["confusion"]
        rows.append(
            {
                "experiment": r["experiment"],
                "TP": c["tp"],
                "FP": c["fp"],
                "FN": c["fn"],
                "TN": c["tn"],
                "precision": m["precision"],
                "recall": m["recall"],
                "f1": m["f1"],
                "fpr": m["false_positive_rate"],
                "specificity": m["specificity"],
                "accuracy": m["accuracy"],
                "balanced_accuracy": m["balanced_accuracy"],
            }
        )
    return rows


def write_csv(results: Iterable[dict], path: str | Path) -> None:
    rows = summary_rows(results)
    if not rows:
        return
    with Path(path).open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
