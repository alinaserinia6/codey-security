"""Centralized environment/configuration for Codey-Security.

The module intentionally uses only the Python standard library so it does not
introduce another runtime dependency just to read .env values.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


PROJECT_ROOT = Path(__file__).resolve().parent


def _load_dotenv(path: Path | None = None) -> None:
    """Load simple KEY=VALUE pairs from .env without overriding real env vars."""
    env_file = path or PROJECT_ROOT / ".env"
    if not env_file.exists():
        return

    for raw_line in env_file.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


_load_dotenv()


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer, got {value!r}") from exc


def _env_float(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number, got {value!r}") from exc


@dataclass(frozen=True)
class Config:
    # LLM provider
    default_llm_provider: str = "ollama"
    openai_api_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    google_api_key: Optional[str] = None
    ollama_host: str = "http://localhost:11434"

    # Model names; leave empty to let the existing provider abstraction choose defaults.
    openai_model: Optional[str] = None
    anthropic_model: Optional[str] = None
    gemini_model: Optional[str] = None
    ollama_model: Optional[str] = None

    # Phase 2
    temperature: float = 0.0
    max_tokens: int = 1800
    max_groups: int = 50
    concurrency: int = 4
    context_radius: int = 8

    # Phase 3
    line_tolerance: int = 5

    # Outputs
    phase1_output: str = "results/phase1_report.json"
    phase2_output: str = "results/phase2_report.json"
    phase3_output: str = "results/phase3_result.json"

    # Runtime
    log_level: str = "INFO"
    debug: bool = False


def get_config() -> Config:
    provider = os.getenv("DEFAULT_LLM_PROVIDER", os.getenv("PHASE2_LLM_PROVIDER", "ollama")).lower()
    if provider == "anthropic":
        provider = "claude"
    if provider not in {"openai", "claude", "gemini", "ollama"}:
        raise ValueError(
            "DEFAULT_LLM_PROVIDER must be one of: openai, claude, gemini, ollama; "
            f"got {provider!r}"
        )

    return Config(
        default_llm_provider=provider,
        openai_api_key=os.getenv("OPENAI_API_KEY") or None,
        anthropic_api_key=os.getenv("ANTHROPIC_API_KEY") or None,
        google_api_key=os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY") or None,
        ollama_host=os.getenv("OLLAMA_HOST", "http://localhost:11434"),
        openai_model=os.getenv("OPENAI_MODEL") or None,
        anthropic_model=os.getenv("ANTHROPIC_MODEL") or os.getenv("CLAUDE_MODEL") or None,
        gemini_model=os.getenv("GEMINI_MODEL") or None,
        ollama_model=os.getenv("OLLAMA_MODEL") or None,
        temperature=_env_float("PHASE2_TEMPERATURE", 0.0),
        max_tokens=_env_int("PHASE2_MAX_TOKENS", 1800),
        max_groups=_env_int("PHASE2_MAX_GROUPS", 50),
        concurrency=max(1, _env_int("PHASE2_CONCURRENCY", 4)),
        context_radius=max(0, _env_int("PHASE2_CONTEXT_RADIUS", 8)),
        line_tolerance=max(0, _env_int("PHASE3_LINE_TOLERANCE", 5)),
        phase1_output=os.getenv("PHASE1_OUTPUT", "results/phase1_report.json"),
        phase2_output=os.getenv("PHASE2_OUTPUT", "results/phase2_report.json"),
        phase3_output=os.getenv("PHASE3_OUTPUT", "results/phase3_result.json"),
        log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
        debug=_env_bool("DEBUG", False),
    )


# Backwards-compatible module-level object for code that expects `config.foo`.
config = get_config()
