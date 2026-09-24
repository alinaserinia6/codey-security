"""Security verification agent.

The agent talks to an external agent/inference server (OpenCode-style session
API). All transport details are hidden behind `analyze()`; the rest of the
pipeline only sees the normalized security assessment dict.
"""

from __future__ import annotations

import asyncio
import json
import os, sys
import textwrap
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

        parts = self._extract_parts(result)

        # Stream reasoning to stderr as soon as it's available.
        if parts["thinking"]:
            try:
                self._thinking_printer(parts["thinking"])
            except Exception:  # noqa: BLE001
                pass

        assessment = self._normalize(
            self._parse_json(parts["text"]), evidence_packet
        )
        assessment["thinking"] = parts["thinking"]
        return assessment

    # ------------------------------------------------------------------
    # Response extraction
    # ------------------------------------------------------------------

    # Part types that carry the model's reasoning rather than the answer.
    _THINKING_PART_TYPES = {"reasoning", "thinking", "analysis", "thought"}
    _IGNORED_PART_TYPES = {"step-start", "step-finish", "tool_call", "tool_result"}

    @classmethod
    def _extract_parts(cls, result: Any) -> Dict[str, str]:
        """Return {"text": ..., "thinking": ...} from an OpenCode response.

        OpenCode emits a `parts` list where each element has a `type`
        discriminator: 'step-start', 'reasoning', 'text', 'step-finish'.
        The reasoning part carries the model's thinking; the text part
        carries the final JSON answer.
        """
        if result is None:
            raise ValueError("LLM returned None")

        # Flatten the top-level Pydantic model so `parts` becomes plain dicts.
        if hasattr(result, "model_dump"):
            try:
                result = result.model_dump()
            except Exception:
                pass

        parts = (
            result.get("parts")
            if isinstance(result, dict)
            else getattr(result, "parts", None)
        )

        text_chunks: List[str] = []
        thinking_chunks: List[str] = []

        if parts:
            for part in parts:
                # Each part is a Pydantic union member; model_dump exposes `type`.
                if hasattr(part, "model_dump"):
                    try:
                        part = part.model_dump()
                    except Exception:
                        pass

                if isinstance(part, dict):
                    ptype = str(part.get("type") or "").lower()
                    ptext = part.get("text")
                else:
                    ptype = str(getattr(part, "type", "") or "").lower()
                    ptext = getattr(part, "text", None)

                if not isinstance(ptext, str) or not ptext.strip():
                    continue

                if ptype in cls._THINKING_PART_TYPES:
                    thinking_chunks.append(ptext)
                elif ptype == "text":
                    text_chunks.append(ptext)
                elif ptype in cls._IGNORED_PART_TYPES:
                    continue
                else:
                    # Unknown type: treat as answer text so nothing is lost.
                    text_chunks.append(ptext)

        # Fallbacks for non-OpenCode servers.
        if not text_chunks:
            for attr in ("text", "content", "message", "output"):
                v = (
                    result.get(attr)
                    if isinstance(result, dict)
                    else getattr(result, attr, None)
                )
                if isinstance(v, str) and v.strip():
                    text_chunks.append(v)
                    break

        if not thinking_chunks:
            for attr in ("reasoning", "thinking", "analysis"):
                v = (
                    result.get(attr)
                    if isinstance(result, dict)
                    else getattr(result, attr, None)
                )
                if isinstance(v, str) and v.strip():
                    thinking_chunks.append(v)
                    break

        if not text_chunks:
            err = (
                result.get("error")
                if isinstance(result, dict)
                else getattr(result, "error", None)
            )
            if err:
                raise ValueError(f"LLM server returned an error: {err}")
            raise ValueError(
                "Could not extract assistant text from LLM response. "
                f"Dump: {str(result)[:500]}"
            )

        return {
            "text": "\n".join(text_chunks),
            "thinking": "\n".join(thinking_chunks),
        }

    # ------------------------------------------------------------------
    # Thinking printer
    # ------------------------------------------------------------------

    @staticmethod
    def _thinking_printer(chunk: str) -> None:
        """Print model reasoning to stderr, word-wrapped inside an open box.

        Long lines are broken at word boundaries so the box never overflows
        the terminal. The top and bottom rules are sized from the actual
        widest content line (plus a small margin), so they always frame the
        text correctly regardless of terminal width.
        """

        chunk = (chunk or "").strip()
        if not chunk:
            return

        # Wrap each paragraph at this column. textwrap handles word
        # boundaries and preserves intentional blank lines.
        wrap_width = 90

        wrapped: list[str] = []
        for raw_line in chunk.splitlines():
            if not raw_line.strip():
                wrapped.append("")
                continue
            # Preserve leading indentation from the model's own formatting.
            indent = len(raw_line) - len(raw_line.lstrip(" "))
            prefix = " " * indent
            pieces = textwrap.wrap(
                raw_line.strip(),
                width=wrap_width - indent,
                break_long_words=False,
                break_on_hyphens=False,
            )
            for piece in pieces:
                wrapped.append(prefix + piece)

        if not wrapped:
            return

        # Top/bottom rules are sized to the longest content line plus margin.
        content_width = max(len(line) for line in wrapped)
        bar_width = max(content_width + 4, 40)

        label = " thinking "
        top = "┌─" + label + "─" * (bar_width - 2 - len(label))
        bottom = "└" + "─" * (bar_width - 1)

        print(f"\n{top}", file=sys.stderr)
        for line in wrapped:
            print(f"│ {line}", file=sys.stderr)
        print(bottom, file=sys.stderr, flush=True)

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
