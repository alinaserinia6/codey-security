"""Security verification agent.

The agent talks to an external agent/inference server (OpenCode-style session
API). All transport details are hidden behind `analyze()`; the rest of the
pipeline only sees the normalized security assessment dict.
"""

from __future__ import annotations

import asyncio
import json
import os
from typing import Any, Dict, List, Optional

from opencode_ai import Opencode
from opencode_ai.types import TextPartInputParam


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
7. Return ONLY one valid JSON object, with no Markdown, no prose, no fences.

Decision meanings:
CONFIRMED = supplied evidence is sufficient to support the vulnerability.
REJECTED = supplied evidence contradicts it or gives a concrete benign explanation.
UNCERTAIN = evidence is insufficient for either conclusion.

JSON schema (this is the only output format accepted):
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


def _safe_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


class SecurityAgent:
    """Single Security Agent backed by an external LLM server."""

    def __init__(
        self,
        *,
        base_url: Optional[str] = None,
        model_id: Optional[str] = None,
        provider_id: Optional[str] = None,
        mode: Optional[str] = None,
        timeout: Optional[float] = None,
        reuse_session: Optional[bool] = None,
    ) -> None:
        self.base_url = (
            base_url
            or os.getenv("LLM_BASE_URL")
            or "http://127.0.0.1:4096"
        )
        self.model_id = (
            model_id
            or os.getenv("LLM_MODEL_ID")
            or "opencode/deepseek-v4-flash-free"
        )
        self.provider_id = (
            provider_id
            or os.getenv("LLM_PROVIDER_ID")
            or "opencode"
        )
        self.mode = (
            mode
            or os.getenv("LLM_MODE")
            or "build"
        )
        self.timeout = float(
            timeout
            if timeout is not None
            else _safe_float(os.getenv("LLM_TIMEOUT"), 300.0)
        )
        self.reuse_session = (
            reuse_session
            if reuse_session is not None
            else os.getenv("LLM_REUSE_SESSION", "false").lower()
            in {"1", "true", "yes", "on"}
        )

        self.client = Opencode(base_url=self.base_url)
        self._session_id: Optional[str] = None
        self._session_lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Session handling
    # ------------------------------------------------------------------
    async def _new_session_id(self) -> str:
        session = await asyncio.to_thread(self.client.session.create)
        session_id = getattr(session, "id", None)
        if session_id is None and isinstance(session, dict):
            session_id = session.get("id")
        if not session_id:
            raise RuntimeError(
                f"LLM server session.create returned no id: {session!r}"
            )
        return str(session_id)

    async def _get_session_id(self) -> str:
        if not self.reuse_session:
            return await self._new_session_id()

        async with self._session_lock:
            if self._session_id is None:
                self._session_id = await self._new_session_id()
            return self._session_id

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    async def analyze(self, evidence_packet: Dict[str, Any]) -> Dict[str, Any]:
        prompt = (
            SECURITY_SYSTEM_PROMPT
            + "\n\nEvidence packet (JSON):\n"
            + json.dumps(evidence_packet, ensure_ascii=False, indent=2, default=str)
            + "\n\nReturn ONLY the JSON object described above."
        )

        session_id = await self._get_session_id()

        chat_call = asyncio.to_thread(
            self.client.session.chat,
            session_id,
            model_id=self.model_id,
            provider_id=self.provider_id,
            mode=self.mode,
            parts=[TextPartInputParam(type="text", text=prompt)],
        )

        try:
            result = await asyncio.wait_for(chat_call, timeout=self.timeout)
        except asyncio.TimeoutError as exc:
            raise TimeoutError(
                f"LLM request timed out after {self.timeout}s"
            ) from exc

        content = self._extract_text(result)
        return self._normalize(self._parse_json(content), evidence_packet)

    # ------------------------------------------------------------------
    # Response extraction
    # ------------------------------------------------------------------
    @staticmethod
    def _extract_text(result: Any) -> str:
        if result is None:
            raise ValueError("LLM returned None")

        parts = getattr(result, "parts", None)
        if parts is None and isinstance(result, dict):
            parts = result.get("parts")

        if parts:
            chunks: List[str] = []
            for part in parts:
                ptype = getattr(part, "type", None)
                if ptype is None and isinstance(part, dict):
                    ptype = part.get("type")
                if ptype is not None and ptype != "text":
                    continue
                text = getattr(part, "text", None)
                if text is None and isinstance(part, dict):
                    text = part.get("text")
                if text:
                    chunks.append(str(text))
            if chunks:
                return "\n".join(chunks)

        for attr in ("text", "content", "message", "output"):
            value = getattr(result, attr, None)
            if value is None and isinstance(result, dict):
                value = result.get(attr)
            if isinstance(value, str) and value.strip():
                return value

        data = getattr(result, "data", None)
        if data is None and isinstance(result, dict):
            data = result.get("data")
        if data is not None and data is not result:
            return SecurityAgent._extract_text(data)

        raise ValueError(
            "Could not extract assistant text from LLM response "
            f"(type={type(result).__name__}): {str(result)[:300]}"
        )

    # ------------------------------------------------------------------
    # JSON parsing
    # ------------------------------------------------------------------
    @staticmethod
    def _parse_json(content: str) -> Dict[str, Any]:
        text = (content or "").strip()
        if not text:
            raise ValueError("LLM returned an empty response")

        if text.startswith("```"):
            text = text.strip("`")
            first_nl = text.find("\n")
            if first_nl != -1:
                maybe_lang = text[:first_nl].strip().lower()
                if maybe_lang in {"json", "jsonc", ""}:
                    text = text[first_nl + 1:]

        head = text[:200].lower()
        if head.startswith("<!doctype") or head.startswith("<html"):
            raise ValueError(
                "LLM server returned HTML instead of JSON. Check that "
                "LLM_BASE_URL points at the API and not at a web UI. "
                f"Response head: {text[:200]!r}"
            )

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

    # ------------------------------------------------------------------
    # Normalization
    # ------------------------------------------------------------------
    @classmethod
    def _normalize(
        cls, value: Dict[str, Any], packet: Dict[str, Any]
    ) -> Dict[str, Any]:
        decision = str(value.get("decision", "UNCERTAIN")).upper()
        if decision not in {"CONFIRMED", "REJECTED", "UNCERTAIN"}:
            decision = "UNCERTAIN"

        confidence = _safe_float(value.get("confidence"), 0.0)
        confidence = max(0.0, min(1.0, confidence))

        def string_list(item: Any) -> List[str]:
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
