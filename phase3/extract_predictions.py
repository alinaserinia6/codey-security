"""Conversion of pipeline reports into benchmark predictions.

Phase 1 reports every tool finding; Phase 2 reports the agent verdicts. Both are
turned into :class:`Prediction` records so the evaluator can match them against
ground truth with one policy.
"""
from __future__ import annotations

from typing import Any, Dict, List

from .models import Prediction

CONFIRMED = "CONFIRMED"


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


def _safe_confidence(value) -> float:
    try:
        return max(0.0, min(1.0, float(value or 0.0)))
    except (TypeError, ValueError):
        return 0.0


def _safe_cwe_list(value) -> List[str]:
    if not value:
        return []
    if isinstance(value, str):
        return [value]
    try:
        return [str(c) for c in value if c]
    except TypeError:
        return [str(value)]


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
                cwe=_safe_cwe_list(finding.get("cwe", [])),
                line=_safe_line(line),
                status=CONFIRMED,
                confidence=_safe_confidence(finding.get("confidence")),
                source=str(finding.get("tool") or "phase1"),
                fingerprint=finding.get("fingerprint"),
                raw=finding,
            )
        )
    return predictions


def predictions_from_phase2(
    report: Dict[str, Any], sample_id: str
) -> List[Prediction]:
    """Only agent groups whose verdict is CONFIRMED are reported.

    REJECTED and UNCERTAIN groups are withheld from the final report by design:
    the verifier is reject-by-default, so a report entry is a claim the agent
    could support with evidence.
    """
    source = _source_of(report)
    predictions: List[Prediction] = []
    for decision in report.get("decisions", []):
        if not isinstance(decision, dict):
            continue
        if str(decision.get("status", "UNCERTAIN")).upper() != CONFIRMED:
            continue
        line = decision.get("line")
        predictions.append(
            Prediction(
                sample_id=sample_id,
                file=str(decision.get("file") or source),
                vulnerable=True,
                cwe=_safe_cwe_list(decision.get("cwe", [])),
                line=_safe_line(line),
                status=CONFIRMED,
                confidence=_safe_confidence(decision.get("confidence")),
                source="phase2",
                raw=decision,
            )
        )
    return predictions
