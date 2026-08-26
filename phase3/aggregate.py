from __future__ import annotations
import csv
import json
from pathlib import Path
from typing import Iterable, List

def load_results(paths: Iterable[str | Path]) -> list[dict]:
    return [json.loads(Path(p).read_text(encoding="utf-8")) for p in paths]

def summary_rows(results: Iterable[dict]) -> list[dict]:
    rows=[]
    for r in results:
        m=r["metrics"]
        c=m["confusion"]
        rows.append({
            "experiment": r["experiment"], "TP": c["tp"], "FP": c["fp"], "FN": c["fn"], "TN": c["tn"],
            "precision": m["precision"], "recall": m["recall"], "f1": m["f1"],
            "fpr": m["false_positive_rate"], "specificity": m["specificity"],
            "accuracy": m["accuracy"], "balanced_accuracy": m["balanced_accuracy"],
        })
    return rows

def write_csv(results: Iterable[dict], path: str | Path) -> None:
    rows=summary_rows(results)
    if not rows: return
    with Path(path).open("w", newline="", encoding="utf-8") as f:
        writer=csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader(); writer.writerows(rows)
