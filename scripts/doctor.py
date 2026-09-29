#!/usr/bin/env python3
"""Environment diagnostics for Codey-Security.

Checks the deterministic toolchain, the Python bindings, the configured
paths (.env / datasets / examples) and, when reachable, the LLM endpoint.
Exits 0 when the Phase-1 toolchain is complete, 1 otherwise. A missing LLM
server is a warning, not a failure, because Phase 1 and Phase-1-only Phase 3
runs never contact it.
"""
from __future__ import annotations

import os
import shutil
import sys
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

failures: list[str] = []
warnings: list[str] = []


def check(label: str, ok: bool, detail: str = "", *, warn_only: bool = False) -> None:
    status = "OK" if ok else ("WARN" if warn_only else "MISSING")
    extra = f": {detail}" if detail else ""
    print(f"{label:18} {status}{extra}")
    if not ok:
        (warnings if warn_only else failures).append(label)


def main() -> int:
    print(f"repo: {REPO_ROOT}")

    for command in ("cppcheck", "flawfinder", "clang", "scan-build"):
        path = shutil.which(command)
        check(command, path is not None, path or "not on PATH")

    try:
        import tree_sitter  # noqa: F401

        check("tree-sitter", True, getattr(tree_sitter, "__version__", "installed"))
    except Exception as exc:
        check("tree-sitter", False, str(exc))

    for module in ("tree_sitter_python", "tree_sitter_c", "tree_sitter_cpp", "bandit"):
        try:
            __import__(module)
            check(module, True, "")
        except Exception as exc:
            check(module, False, str(exc))

    # Configured paths from .env / environment.
    try:
        from env_config import get_config

        config = get_config()
        check("env_config", True, f"architecture={config.phase2_architecture}")
        for name in ("phase1", "phase2", "phase3"):
            scenario = config.scenarios[name]
            ref = scenario.source or scenario.dataset or ""
            exists = bool(ref) and Path(ref).exists()
            check(
                f"scenario:{name}",
                exists,
                ref or "(unset)",
                warn_only=True,
            )
            if not exists:
                warnings.append(f"scenario:{name} -> {ref}")
    except Exception as exc:
        check("env_config", False, f"{type(exc).__name__}: {exc}")

    env_file = REPO_ROOT / ".env"
    check(".env", env_file.exists(), str(env_file) if not env_file.exists() else "", warn_only=True)

    # LLM endpoint: warning only; Phase 1 does not need it.
    base_url = os.getenv("LLM_BASE_URL", "http://127.0.0.1:4096").rstrip("/")
    try:
        with urllib.request.urlopen(base_url + "/", timeout=5) as resp:
            check("llm_server", resp.status < 500, f"{base_url} -> HTTP {resp.status}", warn_only=True)
    except Exception as exc:
        check("llm_server", False, f"{base_url}: {type(exc).__name__}: {exc}", warn_only=True)

    if failures:
        print(f"\n{len(failures)} required check(s) failed: {', '.join(failures)}", file=sys.stderr)
        return 1
    if warnings:
        print(f"\n{len(warnings)} warning(s): {', '.join(warnings)}")
    else:
        print("\nall checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
