from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

from .sanitize import sanitize_source


def load_source_context(path: str | Path, line: Optional[int], radius: int = 8) -> Dict[str, Any]:
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return {"available": False, "error": str(exc), "snippet": ""}

    # Comments and Juliet scenario identifiers would hand the ground-truth
    # label to the agent, so the snippet is sanitized before it is shown.
    language = None
    ext = p.suffix.lower()
    if ext in {".c", ".h"}:
        language = "c"
    elif ext in {".cc", ".cp", ".cpp", ".cxx", ".hh", ".hpp", ".hxx"}:
        language = "cpp"
    elif ext in {".py", ".pyw"}:
        language = "python"

    sanitized = sanitize_source(text, language, path=str(p))
    lines = sanitized.splitlines()

    if not line or line < 1:
        return {"available": True, "start_line": 1, "end_line": min(len(lines), 2 * radius + 1), "snippet": "\n".join(lines[: 2 * radius + 1])}

    start = max(1, line - radius)
    end = min(len(lines), line + radius)
    snippet = "\n".join(f"{n:>6}: {lines[n - 1]}" for n in range(start, end + 1))
    return {"available": True, "start_line": start, "end_line": end, "snippet": snippet}
