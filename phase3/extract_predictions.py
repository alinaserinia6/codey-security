"""Conversion of pipeline reports into benchmark predictions.

Phase 1 reports every tool finding; Phase 2 reports the agent verdicts. Both are
turned into :class:`Prediction` records so the evaluator can match them against
ground truth with one policy.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Tuple

from analyzers.normalize import clamp_confidence, safe_cwe_list

from .models import Prediction

CONFIRMED = "CONFIRMED"
REJECTED = "REJECTED"
UNCERTAIN = "UNCERTAIN"

#: The verdicts a decision can carry, in the order they are reported.
DECISION_STATUSES: Tuple[str, ...] = (CONFIRMED, REJECTED, UNCERTAIN)


def _safe_line(value) -> "int | None":
    """A finding line that is not an integer carries no position information.

    Tool output is untrusted input here (a corrupted report or an
    LLM-shaped dict can carry ``"line": "twelve"``); coercing to None
    keeps one malformed entry from aborting the whole evaluation.
    """
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _source_of(report: Dict[str, Any]) -> str:
    return str(report.get("source") or report.get("path") or "")


def predictions_from_phase1(
    report: Dict[str, Any], sample_id: str
) -> List[Prediction]:
    """Every Phase-1 finding counts as a reported vulnerability.

    The static baseline is deliberately unfiltered: applying the agent verdict
    here would measure the agent, not the tools.
    """
    source = _source_of(report)
    predictions: List[Prediction] = []
    for finding in report.get("findings", []):
        if not isinstance(finding, dict):
            continue
        line = finding.get("line")
        predictions.append(
            Prediction(
                sample_id=sample_id,
                file=str(finding.get("file") or source),
                vulnerable=True,
                cwe=safe_cwe_list(finding.get("cwe", [])),
                line=_safe_line(line),
                status=CONFIRMED,
                confidence=clamp_confidence(finding.get("confidence")),
                source=str(finding.get("tool") or "phase1"),
                fingerprint=finding.get("fingerprint"),
                raw=finding,
            )
        )
    return predictions


def predictions_from_phase2(
    report: Dict[str, Any],
    sample_id: str,
    statuses: Iterable[str] = (CONFIRMED,),
) -> List[Prediction]:
    """Turn agent verdicts into predictions, keeping only the wanted verdicts.

    Only agent groups whose verdict is ``CONFIRMED`` are reported by default:
    the verifier is reject-by-default, so a report entry is a claim the agent
    could support with evidence, and ``REJECTED``/``UNCERTAIN`` groups are
    withheld from the final report by design.

    ``statuses`` exists for offline counterfactual scoring, never for the
    shipped pipeline.  Re-scoring an archived run with
    ``statuses=(CONFIRMED, UNCERTAIN)`` answers "what would recall have been
    had the uncertain verdicts been triaged instead of dropped?" using the
    stored reports, so the question costs no model calls -- see
    ``scripts/policy_counterfactual.py``.  The prediction keeps the verdict it
    actually carried, so a counterfactual table can still tell the two apart.
    """
    wanted = {str(status).upper() for status in statuses}
    unknown = wanted - set(DECISION_STATUSES)
    if unknown:
        raise ValueError(
            f"unknown decision status {sorted(unknown)}; "
            f"expected a subset of {list(DECISION_STATUSES)}"
        )
    source = _source_of(report)
    predictions: List[Prediction] = []
    for decision in report.get("decisions", []):
        if not isinstance(decision, dict):
            continue
        status = str(decision.get("status", UNCERTAIN)).upper()
        if status not in DECISION_STATUSES:
            # The parser normalises an unreadable verdict to UNCERTAIN; do the
            # same here so an archived report with a stray value cannot be
            # silently counted as a confirmation.
            status = UNCERTAIN
        if status not in wanted:
            continue
        line = decision.get("line")
        predictions.append(
            Prediction(
                sample_id=sample_id,
                file=str(decision.get("file") or source),
                vulnerable=True,
                cwe=safe_cwe_list(decision.get("cwe", [])),
                line=_safe_line(line),
                status=status,
                confidence=clamp_confidence(decision.get("confidence")),
                source="phase2",
                raw=decision,
            )
        )
    return predictions
