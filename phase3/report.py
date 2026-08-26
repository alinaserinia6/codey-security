from __future__ import annotations
import json
from pathlib import Path
from typing import Iterable, List
from .evaluator import evaluate
from .models import EvaluationResult, Prediction

def save_result(result: EvaluationResult, path: str | Path) -> None:
    Path(path).write_text(json.dumps(result.to_dict(),indent=2,ensure_ascii=False)+"\n",encoding="utf-8")

def comparison_rows(results: Iterable[EvaluationResult]) -> List[dict]:
    rows=[]
    for r in results:
        m=r.metrics
        rows.append({"experiment":r.experiment,"TP":m.confusion.tp,"FP":m.confusion.fp,"FN":m.confusion.fn,"TN":m.confusion.tn,"Precision":m.precision,"Recall":m.recall,"F1":m.f1,"FPR":m.false_positive_rate,"Accuracy":m.accuracy})
    return rows
