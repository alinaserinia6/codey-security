from __future__ import annotations

import json
from typing import Any, Dict, Optional

from agents.security_agent import SecurityAgent


class Phase2LLM:
    """Compatibility adapter exposing the old Phase2LLM interface.

    Phase 2 is OpenRouter-only and has exactly one Security Agent.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        reasoning_enabled: bool = True,
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ):
        self.reasoning_enabled = reasoning_enabled
        self.agent = SecurityAgent(
            api_key=api_key,
            base_url=base_url,
            model=model,
            reasoning_enabled=reasoning_enabled,
            temperature=temperature,
            max_tokens=max_tokens,
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
