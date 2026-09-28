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


def _row_name(r: dict) -> str:
    """Prefer the human-readable run label over the raw pipeline mode.

    ``experiment`` is set to the pipeline mode (``phase1``/``phase2``/...), so
    comparing several runs of the same mode produces indistinguishable rows.
    The provenance block carries the label used when the run was launched.
    """
    label = (r.get("metadata", {}).get("provenance", {}) or {}).get("label")
    if not label:
        label = (r.get("metadata", {}).get("provenance", {}) or {}).get(
            "experiment"
        )
    if not label:
        return r["experiment"]
    return label if label == r["experiment"] else f"{label} ({r['experiment']})"


def summary_rows(results: Iterable[dict]) -> List[dict]:
    rows = []
    for r in results:
        m = r["metrics"]
        c = m["confusion"]
        sl = (r.get("metadata", {}) or {}).get("sample_level", {}) or {}
        row = {
            "experiment": _row_name(r),
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
        if "benign_flag_rate" in sl:
            row["benign_flag_rate"] = sl["benign_flag_rate"]
        if "vulnerable_detection_rate" in sl:
            row["vulnerable_detection_rate"] = sl["vulnerable_detection_rate"]
        rows.append(row)
    return rows


def write_csv(results: Iterable[dict], path: str | Path) -> None:
    rows = summary_rows(results)
    if not rows:
        return
    with Path(path).open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
