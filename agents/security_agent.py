"""Single LLM-powered security verification agent."""

from __future__ import annotations

import json
import os
from typing import Any, Dict, Optional

from openai import AsyncOpenAI


SECURITY_SYSTEM_PROMPT = """
You are the Security Agent of Codey-Security.

Verify one vulnerability finding produced by deterministic static analysis.

Rules:
1. Use ONLY the supplied evidence.
2. Never invent source code, data-flow, sanitization, bounds checks, runtime
   behavior, or attacker control.
3. Inspect the reported finding, tool evidence, AST/structural information,
   and source context.
4. Be conservative. If important evidence is missing, return UNCERTAIN.
5. Do not modify source code.
6. Preserve the reported CWE unless the supplied evidence clearly contradicts it.
7. Return ONLY one valid JSON object, with no Markdown.

Decision meanings:
CONFIRMED = supplied evidence is sufficient to support the vulnerability.
REJECTED = supplied evidence contradicts it or gives a concrete benign explanation.
UNCERTAIN = evidence is insufficient for either conclusion.

JSON schema:
{
  "decision": "CONFIRMED|REJECTED|UNCERTAIN",
  "confidence": 0.0,
  "rationale": "short technical explanation",
  "evidence": ["specific evidence"],
  "missing_evidence": ["specific missing evidence"],
  "source_location": "file:line or null",
  "cwe": ["CWE-..."],
  "severity": "LOW|MEDIUM|HIGH|CRITICAL|UNKNOWN"
}
""".strip()


def _safe_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


class SecurityAgent:
    """The only LLM agent used by Phase 2.

    It accepts a Phase-1 evidence packet and returns a normalized security
    assessment. The OpenAI client is used only as the transport because the
    LLM API is OpenAI-compatible.
    """

    def __init__(
        self,
        *,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        reasoning_enabled: Optional[bool] = None,
        timeout: float = 120.0,
    ) -> None:
        self.api_key = api_key or os.getenv("LLM_API_KEY")
        self.base_url = (
            base_url
            or os.getenv("LLM_BASE_URL")
            or "https://llm.ai/api/v1"
        )
        self.model = (
            model
            or os.getenv("LLM_MODEL")
            or "deepseek/deepseek-v4-flash-0731:free"
        )
        self.temperature = (
            _safe_float(temperature, _safe_float(os.getenv("LLM_TEMPERATURE"), 0.0))
            if temperature is not None
            else _safe_float(os.getenv("LLM_TEMPERATURE"), 0.0)
        )
        self.max_tokens = (
            _safe_int(max_tokens, _safe_int(os.getenv("LLM_MAX_TOKENS"), 4096))
            if max_tokens is not None
            else _safe_int(os.getenv("LLM_MAX_TOKENS"), 4096)
        )
        self.reasoning_enabled = (
            reasoning_enabled
            if reasoning_enabled is not None
            else os.getenv("LLM_REASONING_ENABLED", "true").lower()
            in {"1", "true", "yes", "on"}
        )
        self.timeout = timeout

        if not self.api_key:
            raise ValueError(
                "LLM_API_KEY is not configured. "
                "Set it in .env or the environment before running Phase 2."
            )

        self.client = AsyncOpenAI(
            api_key=self.api_key,
            base_url=self.base_url.rstrip("/"),
            timeout=self.timeout,
        )

    async def analyze(self, evidence_packet: Dict[str, Any]) -> Dict[str, Any]:
        """Send one evidence packet to DeepSeek and normalize the response."""
        prompt = json.dumps(evidence_packet, ensure_ascii=False, indent=2, default=str)
        response = await self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": SECURITY_SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=self.temperature,
            max_tokens=self.max_tokens,
            response_format={"type": "json_object"},
            extra_body={"reasoning": {"enabled": self.reasoning_enabled}},
        )
        content = response.choices[0].message.content or ""
        return self._normalize(self._parse_json(content), evidence_packet)

    async def process(
        self, prompt: str, context: Optional[Dict[str, Any]] = None
    ) -> str:
        """Compatibility method for the old EnhancedAgent.process interface."""
        payload: Dict[str, Any] = {"task": prompt}
        if context is not None:
            payload["context"] = context
        result = await self.analyze(payload)
        return json.dumps(result, ensure_ascii=False)

    @staticmethod
    def _parse_json(content: str) -> Dict[str, Any]:
        text = (content or "").strip()
        if not text:
            raise ValueError("LLM returned an empty response")
        try:
            value = json.loads(text)
        except json.JSONDecodeError as exc:
            start, end = text.find("{"), text.rfind("}")
            if start < 0 or end <= start:
                raise ValueError(
                    f"LLM returned invalid JSON: {text[:500]}"
                ) from exc
            try:
                value = json.loads(text[start:end + 1])
            except json.JSONDecodeError as nested_exc:
                raise ValueError(
                    f"LLM returned invalid JSON: {text[:500]}"
                ) from nested_exc
        if not isinstance(value, dict):
            raise ValueError("LLM response must be a JSON object")
        return value

    @classmethod
    def _normalize(
        cls, value: Dict[str, Any], packet: Dict[str, Any]
    ) -> Dict[str, Any]:
        decision = str(value.get("decision", "UNCERTAIN")).upper()
        if decision not in {"CONFIRMED", "REJECTED", "UNCERTAIN"}:
            decision = "UNCERTAIN"

        confidence = _safe_float(value.get("confidence"), 0.0)
        confidence = max(0.0, min(1.0, confidence))

        def string_list(item: Any) -> list[str]:
            if item is None:
                return []
            if isinstance(item, list):
                return [str(x) for x in item]
            return [str(item)]

        group = packet.get("group") or {}
        cwe = string_list(value.get("cwe")) or string_list(group.get("cwe"))
        severity = str(
            value.get("severity") or group.get("severity") or "UNKNOWN"
        ).upper()
        if severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"}:
            severity = "UNKNOWN"

        location = value.get("source_location")
        if location is None and group.get("file") and group.get("line") is not None:
            location = f"{group['file']}:{group['line']}"

        return {
            "decision": decision,
            "confidence": confidence,
            "rationale": str(value.get("rationale", "")),
            "evidence": string_list(value.get("evidence")),
            "missing_evidence": string_list(value.get("missing_evidence")),
            "source_location": location,
            "cwe": cwe,
            "severity": severity,
        }
