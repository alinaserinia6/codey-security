"""Derivation of precision/recall/F1 from a confusion matrix.

Two granularities live in a Phase-3 report and they must not be mixed inside
one rate:

* **finding level** -- TP/FP/FN count reported findings. ``precision``,
  ``recall`` and ``f1`` come from here, and so do ``positive_support`` and
  ``negative_support`` on the *finding* population.
* **sample level** -- every cell counts files. This is the only population in
  which ``false_positive_rate``, ``specificity``, ``accuracy`` and
  ``balanced_accuracy`` mean anything.

Deriving the sample-level rates from the finding-level matrix silently produced
numbers that were not comparable between runs. ``TN`` is a count of clean
*files* while ``FP`` is a count of *findings*, so ``FP / (FP + TN)`` has a
denominator that moves with the number of findings a run happens to emit: on
the 60-sample ``vulnllm_r_c_dataflow`` subset it was 86 for the static
baseline (63 findings over 23 clean files), 41 for the LLM-only leg (15 over
26) and 58 for the full leg (30 over 28). A leg that emitted more findings was
therefore charged a *larger* benign denominator, which is how the static
baseline ended up with the worst ``balanced_accuracy`` of the four while its
finding-level precision was simply a different question. Pass the sample-level
matrix and those four rates are computed over files on both sides.
"""
from __future__ import annotations

from math import isfinite
from typing import Optional

from .models import ConfusionMatrix, Metrics


def _div(numerator: float, denominator: float) -> float:
    if not denominator:
        return 0.0
    value = numerator / denominator
    return value if isfinite(value) else 0.0


def compute_metrics(
    cm: ConfusionMatrix,
    *,
    sample_cm: Optional[ConfusionMatrix] = None,
    matched_predictions: int = 0,
    unmatched_predictions: int = 0,
    negative_support: Optional[int] = None,
) -> Metrics:
    """Score one run.

    ``cm`` is the finding-level matrix: TP/FP/FN are findings and TN is the
    number of benign files nothing was reported on. ``precision``/``recall``/
    ``f1`` are computed from it, because those three are defined over findings.

    ``sample_cm`` is the same run counted in files (TP = vulnerable files with
    a matched finding, FP = benign files flagged, and so on). Supply it and the
    benign-side rates come from it. Omit it and they fall back to the mixed
    reading, which is only correct when the caller genuinely has one finding
    per file at most -- the evaluator always has a sample-level matrix
    available, so the fallback exists for direct callers and tests.

    ``negative_support`` is the number of benign files, i.e. the denominator a
    benign-side rate should have. It defaults to the sample matrix's benign
    population and only falls back to ``tn + fp`` when there is no sample
    matrix to read it from.
    """
    tp, fp, fn, tn = cm.tp, cm.fp, cm.fn, cm.tn

    precision = _div(tp, tp + fp)
    recall = _div(tp, tp + fn)
    f1 = _div(2 * precision * recall, precision + recall)

    if sample_cm is not None:
        s_tp, s_fp, s_fn, s_tn = sample_cm.tp, sample_cm.fp, sample_cm.fn, sample_cm.tn
    else:
        # Legacy path: treat the mixed matrix as if its cells were comparable.
        s_tp, s_fp, s_fn, s_tn = tp, fp, fn, tn

    specificity = _div(s_tn, s_tn + s_fp)
    false_positive_rate = _div(s_fp, s_fp + s_tn)
    false_negative_rate = _div(s_fn, s_fn + s_tp)
    accuracy = _div(s_tp + s_tn, s_tp + s_tn + s_fp + s_fn)
    # Balanced accuracy is only meaningful when both classes are populated;
    # otherwise it degenerates into plain recall or specificity.
    balanced = (
        (recall + specificity) / 2
        if (s_tp + s_fn) > 0 and (s_tn + s_fp) > 0
        else 0.0
    )

    if negative_support is None:
        negative_support = (s_tn + s_fp) if sample_cm is not None else (tn + fp)

    return Metrics(
        confusion=cm,
        sample_confusion=ConfusionMatrix(s_tp, s_fp, s_fn, s_tn),
        precision=precision,
        recall=recall,
        f1=f1,
        false_positive_rate=false_positive_rate,
        specificity=specificity,
        false_negative_rate=false_negative_rate,
        accuracy=accuracy,
        balanced_accuracy=balanced,
        positive_support=tp + fn,
        negative_support=negative_support,
        matched_predictions=matched_predictions,
        unmatched_predictions=unmatched_predictions,
    )
