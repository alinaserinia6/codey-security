"""Paired tests for two runs scored on the same population.

Marginal confidence intervals answer "how uncertain is this run"; they cannot
answer "did these two runs actually disagree".  A and C are scored on the same
600 files, so their errors are *paired* -- the right question is how many files
one got right while the other got it wrong, which is McNemar's question.
Comparing two overlapping Wilson intervals and concluding "not distinguishable"
is strictly weaker: with enough samples two intervals can overlap while the
difference is significant, and with few samples they can be disjoint purely
because the marginal estimates are noisy.

Three strata are reported because they are three different questions:

``positive_detection``
    recall, over the vulnerable files only -- did B find a file A missed?
``benign_flagging``
    the false-positive rate, over the clean files only -- did B cry wolf where
    A stayed quiet?
``accuracy``
    every file, scored correct/incorrect -- the net result of the two above.

Both directions of disagreement are reported (``b`` and ``c``), not just the
net, because on this corpus the *counts* carry more information than the
p-value: a "significant" difference resting on three discordant files is a
different claim from one resting on sixty.

No third-party statistics package is used, so the evaluation layer keeps its
zero-dependency profile.
"""
from __future__ import annotations

from math import erfc, sqrt
from typing import Any, Dict, Iterable, Mapping, Tuple

from .models import GroundTruth

#: Above this many discordant pairs ``0.5 ** n`` approaches the float underflow
#: limit and the exact tail cannot be summed in double precision; the
#: chi-square approximation is used instead.  Well above any corpus shipped
#: with this repository.
EXACT_LIMIT = 1000

STRATA = ("positive_detection", "benign_flagging", "accuracy")


def _sig(value: float) -> float:
    """Six significant digits rather than six decimal places.

    ``round(9.1e-13, 10)`` is exactly ``0.0``, and a printed ``p = 0`` claims a
    certainty the test never had: with 41 one-sided discordances the smallest
    p-value the exact test can return is ``2 * 2 ** -41``.  Significant digits
    keep the magnitude that carries the argument while leaving the JSON stable.
    """
    return float(f"{value:.6g}")


def chi_square_mcnemar(b: int, c: int, *, continuity: bool = True) -> float:
    """McNemar's test as a chi-square with 1 degree of freedom.

    ``continuity`` applies the usual -1 correction; it is the conservative
    choice and the default, because the exact test is preferred whenever it is
    computable and this is the fallback for very large discordance counts.
    """
    n = b + c
    if n == 0:
        return 1.0
    difference = abs(b - c)
    if continuity and difference > 0:
        difference -= 1
    chi2 = (difference * difference) / n
    # P(X > chi2) for chi-square with one degree of freedom.
    return erfc(sqrt(chi2 / 2.0))


def exact_mcnemar(b: int, c: int) -> float:
    """Two-sided exact McNemar p-value on the discordant pair counts.

    Under the null the ``b + c`` discordant pairs are a fair coin toss, so the
    two-sided p-value is twice the binomial tail at the smaller of the two
    counts.  Defined at ``b + c = 0`` (p = 1: nothing disagreed) and unlike a
    chi-square approximation it does not pretend to resolve differences of one
    or two files.
    """
    if b < 0 or c < 0:
        raise ValueError(f"discordance counts must be non-negative, got {b}, {c}")
    n = b + c
    if n == 0:
        return 1.0
    if n > EXACT_LIMIT:
        return chi_square_mcnemar(b, c)
    smaller = min(b, c)
    term = 1.0 / (1 << n)  # P(X = 0)
    tail = term
    for i in range(smaller):
        term *= (n - i) / (i + 1)
        tail += term
    return min(1.0, 2.0 * tail)


def discordance(
    outcomes_a: Mapping[str, Any], outcomes_b: Mapping[str, Any]
) -> Tuple[int, int]:
    """``(b, c)``: A-only successes, B-only successes.

    Both mappings must be keyed by the same sample ids; a sample present in one
    and not the other cannot be paired, and silently dropping it would turn a
    paired test into an unpaired one.
    """
    keys_a, keys_b = set(outcomes_a), set(outcomes_b)
    if keys_a != keys_b:
        missing = sorted(keys_a ^ keys_b)[:5]
        raise ValueError(
            "paired test needs identical sample populations; "
            f"{len(keys_a ^ keys_b)} sample ids differ, e.g. {missing}"
        )
    b = c = 0
    for key in keys_a:
        left, right = bool(outcomes_a[key]), bool(outcomes_b[key])
        if left and not right:
            b += 1
        elif right and not left:
            c += 1
    return b, c


def sample_outcomes(
    payload: Mapping[str, Any], ground_truth: Iterable[GroundTruth]
) -> Dict[str, Dict[str, bool]]:
    """Rebuild the per-sample decisions a stored result asserted.

    Taken from ``matches`` and ``unmatched_predictions`` rather than from the
    metrics, because the metrics are aggregates: a paired test needs to know
    *which* files disagreed.  Reading them back also means a run that stores no
    per-sample reports -- the LLM-only leg -- can be compared just as well as
    one that does.
    """
    gts = list(ground_truth)
    positive_ids = {g.sample_id for g in gts if g.vulnerable}
    benign_ids = {g.sample_id for g in gts if not g.vulnerable}

    matches = payload.get("matches") or []
    unmatched = payload.get("unmatched_predictions") or []
    detected = {
        str(match.get("prediction", {}).get("sample_id", ""))
        for match in matches
        if isinstance(match, dict)
    } & positive_ids
    flagged = {
        str(entry.get("sample_id", "")) for entry in unmatched
        if isinstance(entry, dict)
    } & benign_ids

    known = positive_ids | benign_ids
    seen = {
        str(match.get("prediction", {}).get("sample_id", ""))
        for match in matches
        if isinstance(match, dict)
    } | {str(entry.get("sample_id", "")) for entry in unmatched
         if isinstance(entry, dict)}
    unknown = seen - known
    if unknown:
        raise ValueError(
            f"result predicts on {len(unknown)} samples absent from the "
            f"ground truth, e.g. {sorted(unknown)[:5]}"
        )

    return {
        "positive_detection": {sid: sid in detected for sid in positive_ids},
        "benign_flagging": {sid: sid in flagged for sid in benign_ids},
        "accuracy": {
            sid: (sid in detected) if sid in positive_ids else (sid not in flagged)
            for sid in positive_ids | benign_ids
        },
    }


def paired_comparison(
    payload_a: Mapping[str, Any],
    payload_b: Mapping[str, Any],
    ground_truth: Iterable[GroundTruth],
    *,
    method: str = "exact",
) -> Dict[str, Any]:
    """Compare two stored results file-by-file.

    ``method`` is ``"exact"`` (default, the binomial test on the discordant
    pairs) or ``"chi2"``.  Both are returned in the payload's per-stratum
    ``p_value`` as requested, and the exact one additionally under
    ``p_value_exact`` so the choice is never hidden from a reader.
    """
    if method not in ("exact", "chi2"):
        raise ValueError(f"method must be 'exact' or 'chi2', got {method!r}")

    strata_a = sample_outcomes(payload_a, ground_truth)
    strata_b = sample_outcomes(payload_b, ground_truth)

    out: Dict[str, Any] = {"method": method, "strata": {}}
    identical = True
    for name in STRATA:
        outcomes_a, outcomes_b = strata_a[name], strata_b[name]
        b, c = discordance(outcomes_a, outcomes_b)
        n = len(outcomes_a)
        rate_a = (sum(bool(v) for v in outcomes_a.values()) / n) if n else 0.0
        rate_b = (sum(bool(v) for v in outcomes_b.values()) / n) if n else 0.0
        if b or c:
            identical = False
        out["strata"][name] = {
            "n": n,
            "rate_a": round(rate_a, 6),
            "rate_b": round(rate_b, 6),
            "delta_b_minus_a": round(rate_b - rate_a, 6),
            "b_a_only": b,
            "c_b_only": c,
            "p_value": _sig(
                exact_mcnemar(b, c) if method == "exact"
                else chi_square_mcnemar(b, c)
            ),
            "p_value_exact": _sig(exact_mcnemar(b, c)),
            "p_value_chi2": _sig(chi_square_mcnemar(b, c)),
        }
    out["identical"] = identical
    return out
