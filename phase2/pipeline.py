from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from .context import load_source_context
from .llm import Phase2LLM
from .models import AgentAssessment, FinalDecision, Phase2Report
from .prompts import ADJUDICATOR_PROMPT, CONTEXT_PROMPT, CRITIC_PROMPT, SECURITY_PROMPT


@dataclass
class Phase2Config:
    provider: Optional[str] = None
    temperature: float = 0.0
    max_tokens: int = 1800
    context_radius: int = 8
    max_groups: int = 50
    concurrency: int = 4


class Phase2Pipeline:
    """Evidence-aware multi-agent reasoning over a Phase-1 report."""

    def __init__(self, config: Optional[Phase2Config] = None):
        self.cfg = config or Phase2Config(
            provider=os.getenv("PHASE2_LLM_PROVIDER") or os.getenv("DEFAULT_LLM_PROVIDER")
        )
        self.llm = Phase2LLM(
            provider=self.cfg.provider,
            temperature=self.cfg.temperature,
            max_tokens=self.cfg.max_tokens,
        )
        self._sem = asyncio.Semaphore(self.cfg.concurrency)

    async def analyze_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        source = report.get("source") or report.get("path") or "<unknown>"
        language = report.get("language", "unknown")
        groups = list(report.get("metadata", {}).get("correlated_findings", []))[: self.cfg.max_groups]

        phase2 = Phase2Report(
            source=str(source),
            language=str(language),
            metadata={
                "input_finding_count": len(report.get("findings", [])),
                "input_group_count": len(groups),
                "provider": self.cfg.provider,
                "method": "parallel_evidence_agents_then_adjudication",
            },
        )

        tasks = [self._analyze_group(source, language, group, report) for group in groups]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                phase2.errors.append(str(result))
            elif result is not None:
                phase2.decisions.append(result)

        phase2.metadata["decision_counts"] = {
            status: sum(1 for d in phase2.decisions if d.status == status)
            for status in ("CONFIRMED", "REJECTED", "UNCERTAIN")
        }
        return phase2.to_dict()

    async def _analyze_group(
        self,
        source: str,
        language: str,
        group: Dict[str, Any],
        report: Dict[str, Any],
    ) -> Optional[FinalDecision]:
        async with self._sem:
            group_id = group.get("id", "G-UNKNOWN")
            line = group.get("line")
            source_context = load_source_context(source, line, self.cfg.context_radius)

            members = self._members_for_group(group, report.get("findings", []))
            packet = {
                "language": language,
                "group": group,
                "members": members,
                "structural": report.get("metadata", {}).get("structure", {}),
                "source_context": source_context,
            }

            security, context = await asyncio.gather(
                self._assessment("security", SECURITY_PROMPT, packet),
                self._assessment("context", CONTEXT_PROMPT, packet),
            )

            critic_packet = {"evidence_packet": packet, "security_assessment": security.to_dict(), "context_assessment": context.to_dict()}
            critic = await self._assessment("critic", CRITIC_PROMPT, critic_packet)

            final_packet = {
                "original_finding": group,
                "tool_findings": members,
                "security_agent": security.to_dict(),
                "context_agent": context.to_dict(),
                "critic_agent": critic.to_dict(),
            }
            final = await self._adjudicate(final_packet)
            return FinalDecision(
                group_id=group_id,
                file=group.get("file"),
                line=group.get("line"),
                status=final["status"],
                confidence=final["confidence"],
                cwe=final.get("cwe") or group.get("cwe", []),
                severity=final.get("severity") or group.get("severity", "UNKNOWN"),
                rationale=final.get("rationale", ""),
                evidence=final.get("evidence", []),
                agents=[security, context, critic],
                tool_support=group.get("tools", []),
            )

    async def _assessment(self, name: str, system: str, payload: Dict[str, Any]) -> AgentAssessment:
        try:
            value = await self.llm.ask_json(system=system, prompt=json.dumps(payload, ensure_ascii=False, indent=2))
            return AgentAssessment(
                agent=name,
                decision=self._normalize_decision(value.get("decision")),
                confidence=self._clamp_confidence(value.get("confidence")),
                rationale=str(value.get("rationale", "")),
                evidence=self._string_list(value.get("evidence")),
                missing_evidence=self._string_list(value.get("missing_evidence")),
                source_location=value.get("source_location"),
            )
        except Exception as exc:
            return AgentAssessment(agent=name, decision="UNCERTAIN", confidence=0.0, rationale=f"Agent failure: {exc}")

    async def _adjudicate(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        try:
            value = await self.llm.ask_json(system=ADJUDICATOR_PROMPT, prompt=json.dumps(payload, ensure_ascii=False, indent=2))
            return {
                "status": self._normalize_decision(value.get("status")),
                "confidence": self._clamp_confidence(value.get("confidence")),
                "rationale": str(value.get("rationale", "")),
                "evidence": self._string_list(value.get("evidence")),
                "cwe": self._string_list(value.get("cwe")),
                "severity": str(value.get("severity", "UNKNOWN")).upper(),
            }
        except Exception as exc:
            return {
                "status": "UNCERTAIN",
                "confidence": 0.0,
                "rationale": f"Adjudicator failure: {exc}",
                "evidence": [],
                "cwe": [],
                "severity": "UNKNOWN",
            }

    @staticmethod
    def _members_for_group(group: Dict[str, Any], findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        fingerprints = set(group.get("finding_fingerprints", []))
        if not fingerprints:
            return []
        return [f for f in findings if f.get("fingerprint") in fingerprints]

    @staticmethod
    def _normalize_decision(value: Any) -> str:
        value = str(value or "UNCERTAIN").upper()
        return value if value in {"CONFIRMED", "REJECTED", "UNCERTAIN"} else "UNCERTAIN"

    @staticmethod
    def _clamp_confidence(value: Any) -> float:
        try:
            value = float(value)
        except (TypeError, ValueError):
            return 0.0
        return max(0.0, min(1.0, value))

    @staticmethod
    def _string_list(value: Any) -> List[str]:
        if value is None:
            return []
        if isinstance(value, list):
            return [str(x) for x in value]
        return [str(value)]
