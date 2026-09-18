from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .context import load_source_context
from .llm import Phase2LLM
from .models import AgentAssessment, FinalDecision, Phase2Report


@dataclass
class Phase2Config:
    """Runtime configuration for the single-agent Phase 2."""

    deepseek_api_key: Optional[str] = None
    deepseek_base_url: str = "https://api.deepseek.com"
    deepseek_model: str = "deepseek-chat"
    deepseek_temperature: float = 0.0
    deepseek_max_tokens: int = 1800
    context_radius: int = 8
    max_groups: int = 50
    concurrency: int = 4


class Phase2Pipeline:
    """Verify Phase-1 findings using one DeepSeek Security Agent."""

    def __init__(self, config: Optional[Phase2Config] = None):
        self.cfg = config or Phase2Config()
        self.llm = Phase2LLM(
            api_key=self.cfg.deepseek_api_key,
            base_url=self.cfg.deepseek_base_url,
            model=self.cfg.deepseek_model,
            temperature=self.cfg.deepseek_temperature,
            max_tokens=self.cfg.deepseek_max_tokens,
        )
        self._sem = asyncio.Semaphore(max(1, self.cfg.concurrency))

    async def analyze_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        source = report.get("source") or report.get("path") or "<unknown>"
        language = report.get("language", "unknown")
        groups = list(
            report.get("metadata", {}).get("correlated_findings", [])
        )[:self.cfg.max_groups]

        phase2 = Phase2Report(
            source=str(source),
            language=str(language),
            metadata={
                "input_finding_count": len(report.get("findings", [])),
                "input_group_count": len(groups),
                "provider": "deepseek",
                "model": self.cfg.deepseek_model,
                "agent": "security",
                "method": "single_security_agent",
            },
        )

        results = await asyncio.gather(
            *[self._analyze_group(source, language, group, report)
              for group in groups],
            return_exceptions=True,
        )
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
    ) -> FinalDecision:
        async with self._sem:
            line = group.get("line")
            packet = {
                "language": language,
                "group": group,
                "members": self._members_for_group(
                    group, report.get("findings", [])
                ),
                "structural": report.get("metadata", {}).get("structure", {}),
                "source_context": load_source_context(
                    source, line, self.cfg.context_radius
                ),
            }

            try:
                value = await self.llm.ask_json(
                    system="", prompt=json.dumps(
                        packet, ensure_ascii=False, indent=2, default=str
                    )
                )
                assessment = self._assessment_from_result(value, group)
                cwe = self._string_list(value.get("cwe")) or \
                    self._string_list(group.get("cwe"))
                severity = str(
                    value.get("severity") or group.get("severity") or "UNKNOWN"
                ).upper()
            except Exception as exc:
                assessment = AgentAssessment(
                    agent="security",
                    decision="UNCERTAIN",
                    confidence=0.0,
                    rationale=f"Security Agent failure: {exc}",
                    missing_evidence=[
                        "A valid DeepSeek security assessment was not returned."
                    ],
                    source_location=self._location(group),
                )
                cwe = self._string_list(group.get("cwe"))
                severity = str(group.get("severity", "UNKNOWN")).upper()

            return FinalDecision(
                group_id=group.get("id", "G-UNKNOWN"),
                file=group.get("file"),
                line=group.get("line"),
                status=assessment.decision,
                confidence=assessment.confidence,
                cwe=cwe,
                severity=severity,
                rationale=assessment.rationale,
                evidence=assessment.evidence,
                agents=[assessment],
                tool_support=group.get("tools", []),
            )

    @staticmethod
    def _assessment_from_result(
        value: Dict[str, Any], group: Dict[str, Any]
    ) -> AgentAssessment:
        decision = str(value.get("decision", "UNCERTAIN")).upper()
        if decision not in {"CONFIRMED", "REJECTED", "UNCERTAIN"}:
            decision = "UNCERTAIN"
        try:
            confidence = float(value.get("confidence", 0.0))
        except (TypeError, ValueError):
            confidence = 0.0
        return AgentAssessment(
            agent="security",
            decision=decision,
            confidence=max(0.0, min(1.0, confidence)),
            rationale=str(value.get("rationale", "")),
            evidence=Phase2Pipeline._string_list(value.get("evidence")),
            missing_evidence=Phase2Pipeline._string_list(
                value.get("missing_evidence")
            ),
            source_location=value.get("source_location")
            or Phase2Pipeline._location(group),
        )

    @staticmethod
    def _members_for_group(
        group: Dict[str, Any], findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        fingerprints = set(group.get("finding_fingerprints", []))
        return [f for f in findings if f.get("fingerprint") in fingerprints]

    @staticmethod
    def _location(group: Dict[str, Any]) -> Optional[str]:
        if group.get("file") and group.get("line") is not None:
            return f"{group['file']}:{group['line']}"
        return None

    @staticmethod
    def _string_list(value: Any) -> List[str]:
        if value is None:
            return []
        if isinstance(value, list):
            return [str(x) for x in value]
        return [str(value)]
