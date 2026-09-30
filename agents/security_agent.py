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
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from opencode_ai import Opencode
from opencode_ai.types import TextPartInputParam

from . import thinking_log
from .openai_compat import OpenAICompat, TruncatedResponse, resolve_transport


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
8. You have no file-system, shell or search access: the packet is the entire
   evidence. Never try to open, locate, list or read a file — judge from what
   is embedded here.

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


def _is_retryable(exc: BaseException) -> bool:
    """Worth another attempt?

    A timeout, a transport failure or an unparsable reply are all "the
    endpoint had a bad moment" cases — a second try usually succeeds. A
    programming error is not, and retrying it would only double the delay
    before the caller sees it. A reply that was cut off at ``max_tokens``
    is also excluded: the same request would be cut off again.
    """
    if isinstance(exc, TruncatedResponse):
        return False
    return isinstance(exc, (TimeoutError, RuntimeError, ValueError))


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
            or os.getenv("LLM_MODEL")
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
        raw_timeout = (
            timeout
            if timeout is not None
            else _safe_float(os.getenv("LLM_TIMEOUT"), 300.0)
        )
        try:
            raw_timeout = float(raw_timeout)
        except (TypeError, ValueError):
            raw_timeout = 300.0
        # Clamp to a sane range: non-positive/NaN timeouts would otherwise
        # fail every request immediately with a confusing error.
        if not raw_timeout == raw_timeout or raw_timeout <= 0:
            raw_timeout = 300.0
        self.timeout = min(raw_timeout, 3600.0)
        self.reuse_session = (
            reuse_session
            if reuse_session is not None
            else os.getenv("LLM_REUSE_SESSION", "false").lower()
            in {"1", "true", "yes", "on"}
        )

        # `LLM_BASE_URL` selects the wire format: an OpenCode server (the
        # historical local endpoint) or any OpenAI-compatible /v1 API such as
        # https://api.apmix.ai/v1. See agents/openai_compat.py.
        self.transport = resolve_transport(self.base_url)
        if self.transport == "openai":
            self.client = None
            self._openai = OpenAICompat(
                base_url=self.base_url,
                model_id=self.model_id,
                timeout=self.timeout,
            )
        else:
            self._openai = None
            self.client = Opencode(base_url=self.base_url, timeout=self.timeout)
        self._session_id: Optional[str] = None
        self._session_lock = asyncio.Lock()

    def _context(self) -> str:
        return (
            f"transport={self.transport} base_url={self.base_url} "
            f"model={self.model_id} provider={self.provider_id}"
        )

    def _wrap_transport_error(self, exc: BaseException, operation: str) -> RuntimeError:
        """Attach the endpoint identity to a transport/API failure.

        Raw SDK errors say only ``Connection error`` — without the URL and
        model the message is unactionable in logs and reports, so the
        endpoint context is prepended while the original error is chained.
        """
        return RuntimeError(
            f"LLM {operation} failed ({self._context()}): "
            f"{type(exc).__name__}: {exc}"
        )

    # ------------------------------------------------------------------
    # Session handling
    # ------------------------------------------------------------------
    async def _new_session_id(self) -> str:
        try:
            session = await asyncio.wait_for(
                asyncio.to_thread(self.client.session.create),
                timeout=min(self.timeout, 60.0),
            )
        except asyncio.TimeoutError as exc:
            raise TimeoutError(
                f"LLM session.create timed out after {min(self.timeout, 60.0)}s "
                f"(base_url={self.base_url})"
            ) from exc
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

    def _drop_session(self) -> None:
        """Forget a reused session id so the next call starts fresh.

        A stale/invalid session id otherwise poisons every later request
        when ``reuse_session`` is on; dropping it turns one failure into a
        retry instead of a run-wide outage.
        """
        self._session_id = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    async def analyze(
        self,
        evidence_packet: Dict[str, Any],
        *,
        system_prompt: Optional[str] = None,
        normalize: bool = True,
    ) -> Dict[str, Any]:
        """Send one evidence packet and return the model's JSON object.

        ``normalize`` maps the reply onto the Phase 1 single-agent decision
        shape. The Scanner and Verifier roles have their own output contracts
        (``hypotheses`` and ``chain_verified`` respectively), so they pass
        ``normalize=False`` and parse the reply themselves.

        A request that times out, fails in transport or comes back unparsable
        is retried once (``LLM_MAX_ATTEMPTS``, default 2) on a fresh session:
        on a slow free endpoint one dropped or truncated reply is common, and
        retrying costs less than scoring the sample as an error. Every attempt
        — including the failing ones — is appended to the thinking log when
        ``LLM_THINKING_OUT`` is set.
        """
        # Kept as two pieces: the OpenAI-compatible transport sends them as a
        # system + user message pair, while the OpenCode transport forwards
        # the concatenation below, which is byte-for-byte what it always sent.
        system = system_prompt or SECURITY_SYSTEM_PROMPT
        user = (
            "Evidence packet (JSON):\n"
            + json.dumps(evidence_packet, ensure_ascii=False, indent=2, default=str)
            + "\n\nReturn ONLY the JSON object described above."
        )

        identity = thinking_log.current_scope()
        packet_path = evidence_packet.get("file") or evidence_packet.get("path")
        identity.setdefault("id", packet_path or "<unknown>")
        identity.setdefault("file", packet_path)
        identity.setdefault("role", evidence_packet.get("role") or "security")
        identity["model"] = self.model_id

        attempts = self._max_attempts()

        def fail(
            exc: BaseException, attempt: int, started: float, **fields: Any
        ) -> bool:
            """Log a failed attempt; True means it is worth trying again."""
            self._trace(
                dict(
                    identity,
                    attempt=attempt,
                    elapsed=round(time.monotonic() - started, 2),
                ),
                error=f"{type(exc).__name__}: {exc}",
                **fields,
            )
            return attempt < attempts and _is_retryable(exc)

        for attempt in range(1, attempts + 1):
            started = time.monotonic()
            try:
                parts = await self._request(system, user)
            except Exception as exc:  # noqa: BLE001 - recorded, then retried or raised
                if fail(exc, attempt, started):
                    self._drop_session()
                    await asyncio.sleep(min(2.0 * attempt, 10.0))
                    continue
                raise

            # Stream reasoning to stderr as soon as it's available.
            if parts["thinking"]:
                try:
                    self._emit_thinking(parts["thinking"], identity)
                except Exception:  # noqa: BLE001
                    pass

            try:
                assessment = (
                    self._normalize(self._parse_json(parts["text"]), evidence_packet)
                    if normalize
                    else self._parse_json(parts["text"])
                )
            except Exception as exc:  # noqa: BLE001 - truncated/garbled reply
                if fail(
                    exc,
                    attempt,
                    started,
                    thinking=parts["thinking"],
                    answer=parts["text"],
                ):
                    self._drop_session()
                    await asyncio.sleep(min(2.0 * attempt, 10.0))
                    continue
                raise

            self._trace(
                dict(identity, attempt=attempt, elapsed=round(time.monotonic() - started, 2)),
                thinking=parts["thinking"],
                answer=assessment,
            )
            assessment["thinking"] = parts["thinking"]
            return assessment

        raise RuntimeError("unreachable: the attempt loop always returns or raises")

    async def _request(self, system: str, user: str) -> Dict[str, str]:
        """One transport round-trip, returning ``{"text", "thinking"}``."""
        if self._openai is not None:
            return await self._chat_openai(system, user)
        return await self._chat_opencode(
            system + "\n\n" + user if system else user
        )

    async def _chat_openai(self, system: str, user: str) -> Dict[str, str]:
        """POST to an OpenAI-compatible ``/chat/completions`` endpoint."""
        call = asyncio.to_thread(self._openai.chat, system, user)
        try:
            return await asyncio.wait_for(call, timeout=self.timeout)
        except asyncio.TimeoutError as exc:
            raise TimeoutError(
                f"LLM request timed out after {self.timeout}s ({self._context()})"
            ) from exc
        except TruncatedResponse:
            # Already names the knob to turn; wrapping would bury it.
            raise
        except ValueError:
            # The reply was the problem, not the transport: its message is
            # the actionable one and it is logged verbatim per attempt.
            raise
        except Exception as exc:
            raise self._wrap_transport_error(exc, "chat") from exc

    async def _chat_opencode(self, prompt: str) -> Dict[str, str]:
        """Session create + message post against an OpenCode server."""
        try:
            session_id = await self._get_session_id()
        except (asyncio.TimeoutError, TimeoutError):
            # Already carries the endpoint context from _new_session_id;
            # re-wrapping would only bury the timeout type callers log.
            raise
        except Exception as exc:
            raise self._wrap_transport_error(exc, "session.create") from exc

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
            self._drop_session()
            raise TimeoutError(
                f"LLM request timed out after {self.timeout}s ({self._context()})"
            ) from exc
        except Exception as exc:
            # Any transport/API failure (HTTP error codes, connection
            # resets, SDK errors such as httpx.HTTPError which is NOT an
            # OSError) poisons a reused session id; drop it so the next
            # request starts fresh instead of reusing the broken one.
            # The wrapped error keeps propagating: callers record it
            # per sample and continue the run.
            self._drop_session()
            raise self._wrap_transport_error(exc, "chat") from exc

        return self._extract_parts(result)

    @staticmethod
    def _max_attempts() -> int:
        """Total attempts per sample: ``LLM_MAX_ATTEMPTS``, default 2."""
        try:
            value = int(os.getenv("LLM_MAX_ATTEMPTS", "2"))
        except ValueError:
            return 2
        return max(1, value)

    @staticmethod
    def _trace(identity: Dict[str, Any], **fields: Any) -> None:
        thinking_log.record(dict(identity, **fields))

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

    @classmethod
    def _emit_thinking(cls, chunk: str, identity: Optional[Dict[str, Any]] = None) -> None:
        """Show reasoning on stderr according to ``LLM_THINKING_PRINT``.

        ``off`` (silent, the default for benchmark runs), ``short`` (one
        line: role, size and the first words) or ``full`` (the framed box).
        The full trace is always written to ``LLM_THINKING_OUT`` regardless of
        this setting, so a quiet terminal never costs evidence.
        """
        mode = (os.getenv("LLM_THINKING_PRINT") or "").strip().lower()
        if mode in {"off", "none", "0", "false", "no", "silent", "quiet"}:
            return
        if mode in {"full", "box", "all", "1", "true"}:
            cls._thinking_printer(chunk)
            return

        flat = " ".join((chunk or "").split())
        if not flat:
            return
        head = flat[:140] + ("…" if len(flat) > 140 else "")
        role = str((identity or {}).get("role") or "llm")
        target = identity.get("id") if identity else None
        if isinstance(target, str) and target:
            target = Path(target).name
        label = f"{role}|{target}" if target else role
        print(f"  thinking[{label}] {len(chunk)}c: {head}", file=sys.stderr, flush=True)

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
