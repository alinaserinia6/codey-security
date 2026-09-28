"""Derivation of precision/recall/F1 from a confusion matrix."""
from __future__ import annotations

from math import isfinite

from .models import ConfusionMatrix, Metrics


def _div(numerator: float, denominator: float) -> float:
    if not denominator:
        return 0.0
    value = numerator / denominator
    return value if isfinite(value) else 0.0


def compute_metrics(
    cm: ConfusionMatrix,
    *,
    matched_predictions: int = 0,
    unmatched_predictions: int = 0,
) -> Metrics:
    tp, fp, fn, tn = cm.tp, cm.fp, cm.fn, cm.tn

    precision = _div(tp, tp + fp)
    recall = _div(tp, tp + fn)
    f1 = _div(2 * precision * recall, precision + recall)
    specificity = _div(tn, tn + fp)
    false_positive_rate = _div(fp, fp + tn)
    false_negative_rate = _div(fn, fn + tp)
    accuracy = _div(tp + tn, tp + tn + fp + fn)
    # Balanced accuracy is only meaningful when both classes are populated;
    # otherwise it degenerates into plain recall or specificity.
    balanced = (recall + specificity) / 2 if (tp + fn) > 0 and (tn + fp) > 0 else 0.0

    return Metrics(
        confusion=cm,
        precision=precision,
        recall=recall,
        f1=f1,
        false_positive_rate=false_positive_rate,
        specificity=specificity,
        false_negative_rate=false_negative_rate,
        accuracy=accuracy,
        balanced_accuracy=balanced,
        positive_support=tp + fn,
        negative_support=tn + fp,
        matched_predictions=matched_predictions,
        unmatched_predictions=unmatched_predictions,
    )
