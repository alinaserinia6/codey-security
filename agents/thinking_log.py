"""Persist the model's reasoning so a finished run can be audited.

The agent streams its thinking to stderr while a benchmark runs, which means it
is gone the moment the terminal scrolls past. When ``LLM_THINKING_OUT`` points
at a JSON file, every request appends one entry there, grouped by the file that
was analysed, so "what did the model actually look at?" stays answerable after
the fact — including for calls that failed before a decision was reached.

Callers that know *which* sample is in flight (the benchmark harness, the
Scanner/Verifier pipeline) open a :func:`scope`; the transport fills the entry
in because only it sees the reply. Nothing is written when the environment
variable is unset, so tests and static-only runs never touch the disk.
"""
from __future__ import annotations

import contextvars
import json
import os
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, Optional

#: Output file for the reasoning trace. Empty/unset disables recording.
ENV_OUT = "LLM_THINKING_OUT"

#: Long reasoning bursts are kept, but not without bound: one runaway reply
#: must not double the size of every later flush.
MAX_TEXT = 400_000

_scope: contextvars.ContextVar[Optional[Dict[str, Any]]] = contextvars.ContextVar(
    "codey_thinking_scope", default=None
)
_lock = threading.Lock()
_cache: Optional[Dict[str, Any]] = None
_cache_path: Optional[str] = None
_warned = False


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@contextmanager
def scope(**values: Any) -> Iterator[None]:
    """Identify the file/role for requests made inside this block.

    Context-local, so the concurrent workers of a benchmark each describe
    their own sample without sharing state.
    """
    token = _scope.set(dict(values))
    try:
        yield
    finally:
        _scope.reset(token)


def current_scope() -> Dict[str, Any]:
    return dict(_scope.get() or {})


def out_path() -> Optional[Path]:
    raw = os.getenv(ENV_OUT)
    return Path(raw) if raw else None


def _clip(text: Any) -> Any:
    if not isinstance(text, str) or len(text) <= MAX_TEXT:
        return text
    return text[:MAX_TEXT] + f"\n... [truncated, {len(text) - MAX_TEXT} chars]"


def _entry_key(entry: Dict[str, Any]) -> str:
    for key in ("id", "file", "path"):
        value = entry.get(key)
        if value:
            return str(value)
    return "<unknown>"


def _load(path: Path) -> Dict[str, Any]:
    global _cache, _cache_path
    key = str(path)
    if _cache is not None and _cache_path == key:
        return _cache
    data: Dict[str, Any] = {"files": {}}
    if path.exists():
        try:
            parsed = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(parsed, dict) and isinstance(parsed.get("files"), dict):
                data = parsed
        except (OSError, ValueError):
            # A half-written file from an interrupted run must not make the
            # next run lose its trace; start fresh beside it instead.
            data = {"files": {}, "unreadable_previous": True}
    _cache, _cache_path = data, key
    return data


def record(entry: Dict[str, Any]) -> None:
    """Append one request to the trace file. No-op when recording is off."""
    global _warned
    path = out_path()
    if path is None:
        return
    try:
        _record(path, dict(entry))
    except Exception as exc:  # noqa: BLE001 - the trace must never kill a run
        if not _warned:
            _warned = True
            print(
                f"warning: could not write thinking log {path}: "
                f"{type(exc).__name__}: {exc}",
                flush=True,
            )


def _record(path: Path, entry: Dict[str, Any]) -> None:
    key = _entry_key(entry)
    with _lock:
        data = _load(path)
        files = data.setdefault("files", {})
        node = files.setdefault(key, {"file": None, "calls": []})
        if entry.get("file") and not node.get("file"):
            node["file"] = entry["file"]

        call = {k: _clip(v) for k, v in entry.items() if k not in {"id", "file"}}
        call.setdefault("recorded_at", _now())
        node.setdefault("calls", []).append(call)

        data["updated_at"] = _now()
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(
            json.dumps(data, ensure_ascii=False, indent=2, default=str),
            encoding="utf-8",
        )
        os.replace(tmp, path)
