from __future__ import annotations

import json
from typing import Any, Dict, Optional

from agents.security_agent import SecurityAgent


class Phase2LLM:
    """Adapter that exposes the JSON-in / dict-out interface Phase 2 expects."""

    def __init__(
        self,
        *,
        base_url: Optional[str] = None,
        model_id: Optional[str] = None,
        provider_id: Optional[str] = None,
        mode: Optional[str] = None,
        timeout: Optional[float] = None,
        reuse_session: Optional[bool] = None,
    ):
        self.agent = SecurityAgent(
            base_url=base_url,
            model_id=model_id,
            provider_id=provider_id,
            mode=mode,
            timeout=timeout,
            reuse_session=reuse_session,
        )

    async def ask_json(self, *, system: str, prompt: str) -> Dict[str, Any]:
        try:
            payload = json.loads(prompt)
        except json.JSONDecodeError:
            payload = {"task": prompt}
        if not isinstance(payload, dict):
            payload = {"task": payload}
        return await self.agent.analyze(payload)


def parse_json_object(text: str) -> Dict[str, Any]:
    text = (text or "").strip()
    if not text:
        raise ValueError("LLM returned an empty response")
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start < 0 or end <= start:
            raise ValueError("Could not parse JSON object") from None
        value = json.loads(text[start:end + 1])
    if not isinstance(value, dict):
        raise ValueError("Expected a JSON object")
    return value
