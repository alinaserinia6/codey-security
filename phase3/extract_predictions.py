"""Conversion of pipeline reports into benchmark predictions.

Phase 1 reports every tool finding; Phase 2 reports the agent verdicts. Both are
turned into :class:`Prediction` records so the evaluator can match them against
ground truth with one policy.
"""
from __future__ import annotations

from typing import Any, Dict, List

from .models import Prediction

CONFIRMED = "CONFIRMED"


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
        line = finding.get("line")
        predictions.append(
            Prediction(
                sample_id=sample_id,
                file=str(finding.get("file") or source),
                vulnerable=True,
                cwe=[str(cwe) for cwe in finding.get("cwe", [])],
                line=int(line) if line is not None else None,
                status=CONFIRMED,
                confidence=float(finding.get("confidence") or 0.0),
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
        if str(decision.get("status", "UNCERTAIN")).upper() != CONFIRMED:
            continue
        line = decision.get("line")
        predictions.append(
            Prediction(
                sample_id=sample_id,
                file=str(decision.get("file") or source),
                vulnerable=True,
                cwe=[str(cwe) for cwe in decision.get("cwe", [])],
                line=int(line) if line is not None else None,
                status=CONFIRMED,
                confidence=float(decision.get("confidence") or 0.0),
                source="phase2",
                raw=decision,
            )
        )
    return predictions
