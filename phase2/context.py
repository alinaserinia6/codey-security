from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional


def load_source_context(path: str | Path, line: Optional[int], radius: int = 8) -> Dict[str, Any]:
    p = Path(path)
    try:
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        return {"available": False, "error": str(exc), "snippet": ""}

    if not line or line < 1:
        return {"available": True, "start_line": 1, "end_line": min(len(lines), 2 * radius + 1), "snippet": "\n".join(lines[: 2 * radius + 1])}

    start = max(1, line - radius)
    end = min(len(lines), line + radius)
    snippet = "\n".join(f"{n:>6}: {lines[n - 1]}" for n in range(start, end + 1))
    return {"available": True, "start_line": start, "end_line": end, "snippet": snippet}
