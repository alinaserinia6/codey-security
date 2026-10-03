from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

from .sanitize import sanitize_source


def load_source_context(path: str | Path, line: Optional[int], radius: int = 8, bounds: Optional[tuple[int, int]] = None, max_lines: Optional[int] = None) -> Dict[str, Any]:
    """The source around ``line``, widened to the enclosing unit when given one.

    ``radius`` is a line window, and a line window is the wrong unit for judging
    a defect: the property being claimed is usually about a whole operation
    rather than a single line, and the evidence that settles it sits elsewhere
    in the same unit. A window that cuts the unit in half produces confident,
    well-reasoned and wrong answers -- the agent correctly reports that the
    thing it needs "does not appear anywhere in the snippet", which is a
    statement about the snippet.

    On the recorded function-level C benchmark that is not hypothetical. One
    labelled CWE-125 file is 214 lines long; the Scanner put its hypothesis on
    line 31, which is a variable declaration, and ``radius=8`` showed 17 lines
    of declarations. The Verifier answered that no index into the parsed format
    appeared anywhere in the packet -- true of those 17 lines, and false of the
    file. Reasoning correctly about insufficient evidence is still a miss.

    ``bounds`` is the enclosing function's ``(start_line, end_line)``. When it
    is supplied the window is widened to cover it, and ``radius`` is kept as a
    floor so a hypothesis with no function around it still gets a window. A
    caller that cannot supply bounds keeps exactly the old behaviour.
    """
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return {"available": False, "error": str(exc), "snippet": ""}

    # Comments and scenario identifiers would hand the ground-truth
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
    truncated = False
    if bounds is not None:
        unit_start, unit_end = bounds
        if unit_start < unit_end:
            start = max(1, min(start, unit_start))
            end = min(len(lines), max(end, unit_end))
            # A function can be larger than the model's budget, and a snippet
            # that overruns it is truncated by the transport rather than by us --
            # silently, and at the end of the body, which is where the sink
            # usually is. The window is centred on the hypothesis instead, so
            # what survives is the code being asked about, and the context says
            # so rather than implying the agent saw everything.
            if max_lines is not None and end - start + 1 > max_lines:
                keep = max(1, max_lines - (line - start)) if line - start < max_lines else max_lines // 2
                start = max(start, line - keep)
                end = min(end, start + max_lines - 1)
                truncated = True
    snippet = "\n".join(f"{n:>6}: {lines[n - 1]}" for n in range(start, end + 1))
    context: Dict[str, Any] = {
        "available": True,
        "start_line": start,
        "end_line": end,
        "snippet": snippet,
    }
    if truncated:
        context["truncated"] = True
        context["note"] = (
            f"window capped at {max_lines} lines; the enclosing unit is larger, "
            "so this is not the whole of it"
        )
    return context
