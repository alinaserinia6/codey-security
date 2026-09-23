"""Central runtime configuration for Codey-Security.

The CLI only selects a pipeline command. Runtime settings and scenario paths are
kept here and can be overridden with a local .env file.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
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


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


def _env_str(name: str, default: str) -> str:
    value = os.getenv(name)
    return value if value is not None and value != "" else default


def _path(value: str) -> str:
    path = Path(value).expanduser()
    return str(path if path.is_absolute() else PROJECT_ROOT / path)


@dataclass(frozen=True)
class ScenarioConfig:
    """Input/output references for one pipeline command."""

    source: Optional[str] = None
    dataset: Optional[str] = None
    mode: str = "phase1"
    output: str = "results/report.json"
    phase1_output: Optional[str] = None
    phase2_output: Optional[str] = None
    evaluation_output: Optional[str] = None
    skip_missing: bool = False
    require_cwe_match: bool = True


@dataclass(frozen=True)
class Config:
    """Runtime settings for the single-agent pipeline.

    LLM settings are provider-neutral. They describe *where* to reach an
    OpenAI-style / agent-style inference server and *how* to call it. The
    concrete SDK that implements the transport lives entirely inside
    `agents/security_agent.py`.
    """

    # --- LLM transport --------------------------------------------------
    llm_base_url: str = "http://127.0.0.1:4096"
    llm_model_id: str = "opencode/deepseek-v4-flash-free"
    llm_provider_id: str = "opencode"
    llm_mode: str = "build"
    llm_timeout: float = 300.0
    llm_reuse_session: bool = False

    # --- Phase 2 execution ---------------------------------------------
    phase2_max_groups: int = 50
    phase2_concurrency: int = 4
    phase2_context_radius: int = 8

    # --- Phase 3 matching ----------------------------------------------
    phase3_line_tolerance: int = 5

    scenarios: dict[str, ScenarioConfig] = field(default_factory=dict)


def _make_scenarios() -> dict[str, ScenarioConfig]:
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
            dataset=(
                _path(os.getenv("SCENARIO_FULL_DATASET", ""))
                if os.getenv("SCENARIO_FULL_DATASET")
                else None
            ),
            mode=os.getenv("SCENARIO_FULL_MODE", "phase2").lower(),
            phase1_output=_path(os.getenv("SCENARIO_FULL_PHASE1_OUTPUT", "results/phase1_report.json")),
            phase2_output=_path(os.getenv("SCENARIO_FULL_PHASE2_OUTPUT", "results/phase2_report.json")),
            evaluation_output=_path(os.getenv("SCENARIO_FULL_EVALUATION_OUTPUT", "results/phase3_result.json")),
            require_cwe_match=_env_bool("SCENARIO_FULL_REQUIRE_CWE", True),
        ),
    }


def get_config() -> Config:
    return Config(
        llm_base_url=_env_str("LLM_BASE_URL", "http://127.0.0.1:4096").rstrip("/"),
        llm_model_id=_env_str("LLM_MODEL_ID", "opencode/deepseek-v4-flash-free"),
        llm_provider_id=_env_str("LLM_PROVIDER_ID", "opencode"),
        llm_mode=_env_str("LLM_MODE", "build"),
        llm_timeout=_env_float("LLM_TIMEOUT", 300.0),
        llm_reuse_session=_env_bool("LLM_REUSE_SESSION", False),
        phase2_max_groups=max(1, _env_int("PHASE2_MAX_GROUPS", 50)),
        phase2_concurrency=max(1, _env_int("PHASE2_CONCURRENCY", 4)),
        phase2_context_radius=max(0, _env_int("PHASE2_CONTEXT_RADIUS", 8)),
        phase3_line_tolerance=max(0, _env_int("PHASE3_LINE_TOLERANCE", 5)),
        scenarios=_make_scenarios(),
    )


config = get_config()
