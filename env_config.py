"""Central configuration for Codey-Security.

The CLI is intentionally minimal: users choose only a command, e.g.
`python codey_security.py phase2` or `python codey_security.py full`.
All other runtime settings, input references and scenario parameters live here
(or in environment variables loaded from .env).
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

PROJECT_ROOT = Path(__file__).resolve().parent


def _load_dotenv(path: Path | None = None) -> None:
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


def _path(value: str) -> str:
    """Resolve relative paths against the project root while keeping output readable."""
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return str(path)


@dataclass(frozen=True)
class ScenarioConfig:
    """Everything specific to one CLI scenario."""

    # Main input reference. Phase 3 uses `dataset` instead.
    source: Optional[str] = None
    dataset: Optional[str] = None

    # Phase 3 benchmark mode.
    mode: str = "phase1"

    # Outputs for that scenario.
    output: str = "results/report.json"
    phase1_output: Optional[str] = None
    phase2_output: Optional[str] = None
    evaluation_output: Optional[str] = None

    # Benchmark behavior.
    skip_missing: bool = False
    require_cwe_match: bool = True


@dataclass(frozen=True)
class Config:
    # ------------------------------------------------------------------
    # Global LLM configuration
    # ------------------------------------------------------------------
    default_llm_provider: str = "deepseek"
    openai_api_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    google_api_key: Optional[str] = None
    deepseek_api_key: Optional[str] = None
    deepseek_base_url: str = "https://api.deepseek.com"
    deepseek_model: str = "deepseek-chat"
    ollama_host: str = "http://localhost:11434"

    openai_model: Optional[str] = None
    anthropic_model: Optional[str] = None
    gemini_model: Optional[str] = None
    ollama_model: Optional[str] = None

    # ------------------------------------------------------------------
    # Phase 2
    # ------------------------------------------------------------------
    temperature: float = 0.0
    max_tokens: int = 1800
    max_groups: int = 50
    concurrency: int = 4
    context_radius: int = 8

    # ------------------------------------------------------------------
    # Phase 3
    # ------------------------------------------------------------------
    line_tolerance: int = 5

    # ------------------------------------------------------------------
    # Runtime
    # ------------------------------------------------------------------
    log_level: str = "INFO"
    debug: bool = False

    # ------------------------------------------------------------------
    # Scenario references
    # ------------------------------------------------------------------
    scenarios: dict[str, ScenarioConfig] = None  # type: ignore[assignment]


def _make_scenarios() -> dict[str, ScenarioConfig]:
    """Build all CLI scenarios from environment variables.

    This is the single place where a scenario points to a source file,
    dataset, or result file. Therefore the CLI needs no path/options.
    """

    return {
        "phase1": ScenarioConfig(
            source=_path(os.getenv("SCENARIO_PHASE1_SOURCE", "examples/cpp/vulnerable.cpp")),
            output=_path(os.getenv("SCENARIO_PHASE1_OUTPUT", "results/phase1_report.json")),
        ),
        "phase2": ScenarioConfig(
            source=_path(os.getenv("SCENARIO_PHASE2_SOURCE", "examples/cpp/vulnerable.cpp")),
            output=_path(os.getenv("SCENARIO_PHASE2_OUTPUT", "results/phase2_report.json")),
        ),
        "phase3": ScenarioConfig(
            dataset=_path(os.getenv("SCENARIO_PHASE3_DATASET", "datasets/juliet_test.json")),
            mode=os.getenv("SCENARIO_PHASE3_MODE", "phase1").lower(),
            output=_path(os.getenv("SCENARIO_PHASE3_OUTPUT", "results/phase3_result.json")),
            skip_missing=_env_bool("SCENARIO_PHASE3_SKIP_MISSING", False),
            require_cwe_match=_env_bool("SCENARIO_PHASE3_REQUIRE_CWE", True),
        ),
        "full": ScenarioConfig(
            source=_path(os.getenv("SCENARIO_FULL_SOURCE", "examples/cpp/vulnerable.cpp")),
            dataset=_path(os.getenv("SCENARIO_FULL_DATASET", "")) if os.getenv("SCENARIO_FULL_DATASET") else None,
            mode=os.getenv("SCENARIO_FULL_MODE", "phase2").lower(),
            phase1_output=_path(os.getenv("SCENARIO_FULL_PHASE1_OUTPUT", "results/phase1_report.json")),
            phase2_output=_path(os.getenv("SCENARIO_FULL_PHASE2_OUTPUT", "results/phase2_report.json")),
            evaluation_output=_path(os.getenv("SCENARIO_FULL_EVALUATION_OUTPUT", "results/phase3_result.json")),
            require_cwe_match=_env_bool("SCENARIO_FULL_REQUIRE_CWE", True),
        ),
    }


def get_config() -> Config:
    # Phase 2 is intentionally DeepSeek-only.
    provider = "deepseek"

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
        max_groups=max(1, _env_int("PHASE2_MAX_GROUPS", 50)),
        concurrency=max(1, _env_int("PHASE2_CONCURRENCY", 4)),
        context_radius=max(0, _env_int("PHASE2_CONTEXT_RADIUS", 8)),
        line_tolerance=max(0, _env_int("PHASE3_LINE_TOLERANCE", 5)),
        log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
        debug=_env_bool("DEBUG", False),
        scenarios=_make_scenarios(),
    )


config = get_config()
