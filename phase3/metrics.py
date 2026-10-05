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

Every rate is reported with a Wilson score interval in ``Metrics.ci95``: the
benchmark's true-positive counts are small enough (three for configuration C)
that the point estimate alone says almost nothing, and an interval is the only
honest way to read them. ``f1`` is deliberately absent -- it is not a binomial
proportion, so a Wilson interval over it would be meaningless.
"""
from __future__ import annotations

from math import isfinite, sqrt
from typing import Dict, List, Optional, Sequence, Tuple

from .models import ConfusionMatrix, Metrics

#: 97.5th percentile of the standard normal, i.e. z for a two-sided 95%
#: interval.  Hard-coded rather than pulled from a statistics package so the
#: evaluation layer keeps its zero-dependency profile.
Z_95 = 1.959963984540054


def wilson_interval(
    successes: int, trials: int, z: float = Z_95
) -> Tuple[float, float]:
    """Wilson score interval for a binomial proportion.

    A normal approximation is worthless at the sample sizes this benchmark
    actually has: configuration C reports three true positives, where
    ``p ± 1.96·SE`` produces an interval that runs below zero and a run with a
    single success would report ``0 ± 0.98``.  The Wilson score interval stays
    inside ``[0, 1]``, is defined at ``x = 0`` and ``x = n``, and is the
    interval the thesis quotes -- so the numbers printed in the evaluation
    chapter are reproducible from the archived results instead of being
    transcribed by hand.

    ``trials == 0`` carries no information at all, so the whole range is
    returned.
    """
    if trials <= 0:
        return (0.0, 1.0)
    if successes < 0 or successes > trials:
        raise ValueError(
            f"successes must be within [0, trials]; got {successes}/{trials}"
        )
    n = float(trials)
    p = successes / n
    z2 = z * z
    denom = 1.0 + z2 / n
    center = (p + z2 / (2.0 * n)) / denom
    half = (z * sqrt((p * (1.0 - p) / n) + (z2 / (4.0 * n * n)))) / denom
    # Wilson's lower bound at x = 0 is exactly 0 and its upper bound at
    # x = n is exactly 1; the subtraction above lands a few ulps off, and
    # printing 8.7e-19 as a lower bound would read as a claim.
    low = 0.0 if successes == 0 else max(0.0, center - half)
    high = 1.0 if successes == trials else min(1.0, center + half)
    return (low, high)


def _round_bounds(interval: Sequence[float]) -> List[float]:
    return [round(float(interval[0]), 6), round(float(interval[1]), 6)]


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

    ci95: Dict[str, List[float]] = {}
    for name, successes, trials in (
        ("precision", tp, tp + fp),
        ("recall", tp, tp + fn),
        ("false_positive_rate", s_fp, s_fp + s_tn),
        ("specificity", s_tn, s_tn + s_fp),
        ("false_negative_rate", s_fn, s_fn + s_tp),
        ("accuracy", s_tp + s_tn, s_tp + s_tn + s_fp + s_fn),
    ):
        if trials > 0:
            ci95[name] = _round_bounds(wilson_interval(successes, trials))

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
        ci95=ci95,
    )
