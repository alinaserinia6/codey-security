from __future__ import annotations

import json
from typing import Any, Dict, Optional

class Phase2LLM:
    """Small adapter around the project's existing provider abstraction."""

    def __init__(self, provider: Optional[str] = None, temperature: float = 0.0, max_tokens: int = 1800):
        if provider is None:
            try:
                from env_config import config
                provider = config.default_llm_provider
            except ImportError:
                provider = "openai"
        if provider not in {"openai", "claude", "gemini", "ollama"}:
            raise ValueError(f"Unsupported Phase-2 LLM provider: {provider}")
        self.provider = provider
        self.temperature = temperature
        self.max_tokens = max_tokens

    async def ask_json(self, *, system: str, prompt: str) -> Dict[str, Any]:
        from agents.enhanced_multi_agent_system import AgentConfig, EnhancedAgent

        agent = EnhancedAgent(
            AgentConfig(
                name="phase2_agent",
                role="Phase 2 Analyst",
                llm_provider=self.provider,
                system_message=system,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
            )
        )
        raw = await agent.process(prompt)
        return parse_json_object(raw)


def parse_json_object(text: str) -> Dict[str, Any]:
    """Parse JSON even when a model wraps it in markdown fences or extra text."""
    text = (text or "").strip()
    if not text:
        raise ValueError("LLM returned an empty response")

    candidates = [text]
    if "```" in text:
        parts = text.split("```")
        for part in parts:
            cleaned = part.strip()
            if cleaned.startswith("json"):
                cleaned = cleaned[4:].strip()
            if cleaned:
                candidates.append(cleaned)

    decoder = json.JSONDecoder()
    for candidate in candidates:
        try:
            value = json.loads(candidate)
            if isinstance(value, dict):
                return value
        except json.JSONDecodeError:
            pass

        # Recover the first JSON object embedded in prose.
        start = candidate.find("{")
        while start >= 0:
            try:
                value, _ = decoder.raw_decode(candidate[start:])
                if isinstance(value, dict):
                    return value
            except json.JSONDecodeError:
                start = candidate.find("{", start + 1)
                continue
            break

    raise ValueError(f"Could not parse JSON object from LLM response: {text[:500]}")
