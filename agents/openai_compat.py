"""OpenAI-compatible ``/chat/completions`` transport.

``agents.security_agent`` talks to an OpenCode server by default: it creates a
conversation with ``POST /session`` and sends the prompt to
``POST /session/{id}/message``. Hosted providers (Apmix, OpenRouter, ...) and
local OpenAI-compatible servers (vLLM, Ollama, ...) only speak the plain
``/v1/chat/completions`` API, so those session routes answer 404 and every
sample in a run degrades into an error.

This module implements that dialect and returns the same
``{"text", "thinking"}`` envelope the OpenCode path produces, so nothing
downstream has to know which wire format was used: reasoning that
OpenAI-compatible servers put in ``message.reasoning_content`` becomes
``thinking``, the answer in ``message.content`` becomes ``text``.
"""
from __future__ import annotations

import os
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import httpx

#: Explicit transport names accepted in ``LLM_TRANSPORT``.
OPENAI_TRANSPORT = "openai"
OPENCODE_TRANSPORT = "opencode"

_OPENAI_ALIASES = {
    OPENAI_TRANSPORT,
    "openai-compat",
    "openai_compatible",
    "openai-compatible",
    "openai_api",
}
_OPENCODE_ALIASES = {OPENCODE_TRANSPORT, "opencode-server", "opencode_server"}


class TruncatedResponse(ValueError):
    """The reply hit ``max_tokens`` before it finished.

    A budget that was too small stays too small, so re-sending the identical
    request only burns the retry; the message names the knob to turn instead.
    """


class UpstreamError(Exception):
    """The provider answered with an HTTP error (401, 429, 503, ...).

    Deliberately not a ``RuntimeError`` so the wrapped message reads
    ``RuntimeError: LLM chat failed (...): UpstreamError: HTTP 503 ...``
    instead of naming the same type twice. SecurityAgent wraps it into a
    retryable error, which is what turns a transient 503 into a second
    attempt rather than a failed sample.
    """


def resolve_transport(base_url: str, mode: Optional[str] = None) -> str:
    """Which wire protocol ``base_url`` speaks: ``openai`` or ``opencode``.

    ``LLM_TRANSPORT`` (or the explicit ``mode``) always wins. Without it, a
    base URL whose path ends in ``/v1`` — or that already points at
    ``/chat/completions`` — is an OpenAI-style API; everything else is an
    OpenCode server, which is what a bare ``http://127.0.0.1:4096`` is.
    """
    chosen = (mode or os.getenv("LLM_TRANSPORT") or "auto").strip().lower()
    if chosen in _OPENAI_ALIASES:
        return OPENAI_TRANSPORT
    if chosen in _OPENCODE_ALIASES:
        return OPENCODE_TRANSPORT
    path = urlparse(base_url or "").path.rstrip("/")
    if path.endswith("/v1") or path.endswith("/chat/completions"):
        return OPENAI_TRANSPORT
    return OPENCODE_TRANSPORT


def chat_url(base_url: str) -> str:
    """Absolute ``/chat/completions`` URL for an OpenAI-style base URL.

    ``https://api.apmix.ai/v1`` -> ``https://api.apmix.ai/v1/chat/completions``;
    a bare host gains the conventional ``/v1`` prefix, and a URL that already
    ends in the endpoint is used as-is.
    """
    base = (base_url or "").strip().rstrip("/")
    if not base:
        raise ValueError("LLM_BASE_URL is empty")
    if base.endswith("/chat/completions"):
        return base
    if base.endswith("/v1"):
        return base + "/chat/completions"
    return base + "/v1/chat/completions"


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or not str(raw).strip():
        return default
    try:
        return int(str(raw).strip())
    except ValueError:
        return default


def _env_float(name: str, default: float) -> Optional[float]:
    raw = os.getenv(name)
    if raw is None or not str(raw).strip():
        return default
    try:
        return float(str(raw).strip())
    except ValueError:
        return default


def _first_string(mapping: Dict[str, Any], *names: str) -> str:
    for name in names:
        value = mapping.get(name)
        if isinstance(value, str) and value.strip():
            return value
    return ""


def _content_to_text(content: Any) -> str:
    """``content`` may be a string or a list of typed blocks."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        chunks = []
        for block in content:
            if isinstance(block, dict):
                text = block.get("text")
                if isinstance(text, str):
                    chunks.append(text)
            elif isinstance(block, str):
                chunks.append(block)
        return "".join(chunks)
    return ""


def envelope(data: Any, *, max_tokens: int) -> Dict[str, Any]:
    """Turn an OpenAI chat-completion body into ``{"text", "thinking", "usage"}``.

    ``usage`` is the provider's token accounting (prompt/completion/reasoning)
    so the thinking log can show what a run actually spent; it is ``{}`` for a
    body that carries none.
    """
    if not isinstance(data, dict):
        raise ValueError(f"LLM returned a non-object reply: {str(data)[:300]}")

    choices = data.get("choices")
    if not choices:
        error = data.get("error")
        raise ValueError(
            f"LLM reply has no choices: {str(error or data)[:300]}"
        )

    choice = choices[0] if isinstance(choices[0], dict) else {}
    message = choice.get("message") or {}
    if not isinstance(message, dict):
        message = {}

    text = _content_to_text(message.get("content")).strip()
    thinking = _first_string(
        message, "reasoning_content", "reasoning", "thinking", "analysis"
    )
    finish = str(choice.get("finish_reason") or "").lower()

    if finish == "length":
        raise TruncatedResponse(
            f"response cut off at max_tokens={max_tokens}; raise LLM_MAX_TOKENS"
        )
    if not text:
        refusal = _first_string(message, "refusal")
        raise ValueError(
            "LLM reply has no content"
            + (f": {refusal}" if refusal else "")
            + f" (finish_reason={finish or 'unknown'})"
        )
    return {"text": text, "thinking": thinking, "usage": data.get("usage") or {}}


class OpenAICompat:
    """Blocking ``/chat/completions`` client.

    One instance per :class:`~agents.security_agent.SecurityAgent`; the agent
    runs :meth:`chat` in a worker thread, so this class deliberately has no
    async API. ``httpx.Client`` is thread-safe and keeps connections pooled
    across a run, and is closed at interpreter exit.

    ``max_tokens`` is a *starting* budget: a reasoning model that spends its
    whole allowance on thinking answers with ``finish_reason="length"`` and no
    usable reply, so :meth:`chat` doubles the budget (up to ``max_tokens_cap``)
    and asks again rather than turning the sample into an error. The raised
    budget sticks for the rest of the run, so only the first sample pays the
    exploration cost.

    ``reasoning_effort`` (``LLM_REASONING_EFFORT``) caps the *hidden* thinking
    before the answer, which is where a reasoning model spends most of its
    output tokens.
    """

    #: How many times the budget may be doubled inside one :meth:`chat`.
    _MAX_ESCALATIONS = 3

    def __init__(
        self,
        *,
        base_url: str,
        model_id: str,
        api_key: Optional[str] = None,
        timeout: float = 300.0,
        max_tokens: Optional[int] = None,
        max_tokens_cap: Optional[int] = None,
        temperature: Optional[float] = None,
        reasoning_effort: Optional[str] = None,
    ) -> None:
        self.base_url = base_url
        self.url = chat_url(base_url)
        self.model_id = model_id
        self.timeout = float(timeout)
        self.max_tokens = int(
            max_tokens if max_tokens is not None else _env_int("LLM_MAX_TOKENS", 4096)
        )
        self.max_tokens_cap = max(
            self.max_tokens,
            int(
                max_tokens_cap
                if max_tokens_cap is not None
                else _env_int("LLM_MAX_TOKENS_CAP", 65536)
            ),
        )
        self.temperature = (
            temperature
            if temperature is not None
            else _env_float("LLM_TEMPERATURE", None)
        )
        # ``reasoning_effort`` ("minimal" | "low" | "medium" | "high") is the
        # provider's knob for how many hidden reasoning tokens to spend before
        # answering. It dominates the bill: on this endpoint "minimal" answers
        # with 0 reasoning tokens where the default spends ~150, and a run is
        # mostly reasoning (5-6k chars of thinking behind a 1-2k char answer).
        # Empty means "do not send the field" and the provider decides.
        self.reasoning_effort = (
            reasoning_effort
            if reasoning_effort is not None
            else (os.getenv("LLM_REASONING_EFFORT") or "")
        ).strip()
        self._effort_dropped = False

        key = api_key if api_key is not None else os.getenv("LLM_API_KEY") or ""
        key = key.strip()
        if not key:
            key = (os.getenv("OPENAI_API_KEY") or "").strip()
        self.has_api_key = bool(key)

        headers = {"Accept": "application/json"}
        if key:
            headers["Authorization"] = f"Bearer {key}"

        import atexit

        self._client = httpx.Client(
            timeout=self.timeout,
            headers=headers,
            follow_redirects=True,
        )
        atexit.register(self._close)

    def _close(self) -> None:
        try:
            self._client.close()
        except Exception:  # noqa: BLE001 - shutdown must never raise
            pass

    def chat(self, system: str, user: str) -> Dict[str, str]:
        """Send one prompt; returns ``{"text", "thinking"}``."""
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": user})

        payload: Dict[str, Any] = {
            "model": self.model_id,
            "messages": messages,
            "stream": False,
        }
        if self.temperature is not None:
            payload["temperature"] = self.temperature
        if self.reasoning_effort and not self._effort_dropped:
            payload["reasoning_effort"] = self.reasoning_effort

        escalations = 0
        while True:
            payload["max_tokens"] = self.max_tokens
            response = self._client.post(self.url, json=payload)
            if response.status_code >= 400:
                # A provider that does not know reasoning_effort rejects every
                # request with a 400 naming the field (or the body in general).
                # Drop it for the rest of the run and ask again, so one unknown
                # parameter cannot turn every sample into a failure: the field
                # is popped, so this branch cannot fire a second time.
                if (
                    response.status_code == 400
                    and "reasoning_effort" in payload
                ):
                    self._effort_dropped = True
                    payload.pop("reasoning_effort", None)
                    continue
                # Body first: providers put the real reason (bad model id,
                # expired key, rate limit) there, not in the status line.
                raise UpstreamError(
                    f"HTTP {response.status_code} from {self.url}: "
                    f"{response.text[:400]}"
                )
            try:
                data = response.json()
            except ValueError as exc:
                raise ValueError(
                    f"LLM returned a non-JSON body: {response.text[:300]}"
                ) from exc
            try:
                return envelope(data, max_tokens=self.max_tokens)
            except TruncatedResponse as exc:
                if escalations >= self._MAX_ESCALATIONS:
                    raise TruncatedResponse(
                        f"{exc} (stopped escalating after "
                        f"{self._MAX_ESCALATIONS} doubling(s))"
                    ) from None
                if not self._grow_budget():
                    raise TruncatedResponse(
                        f"{exc} (LLM_MAX_TOKENS_CAP={self.max_tokens_cap} reached)"
                    ) from None
                escalations += 1

    def _grow_budget(self) -> bool:
        """Double the output budget; False when the cap is already reached."""
        if self.max_tokens >= self.max_tokens_cap:
            return False
        self.max_tokens = min(self.max_tokens * 2, self.max_tokens_cap)
        return True
