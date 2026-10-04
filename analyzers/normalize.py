"""Normalization of scalar fields that arrive from outside the process.

Confidence scores and CWE ids come from three places that are all untrusted:
static-tool output, corpus rows and an LLM's JSON reply. Each place used to
coerce them with its own inline code, and the differences mattered -- most
notably ``max(0.0, min(1.0, nan))`` evaluates to ``1.0`` in Python, so a
garbled confidence quietly became the strongest possible one.
"""
from __future__ import annotations

from math import isfinite
from typing import Any, List


def clamp_confidence(value: Any) -> float:
    """Coerce an untrusted confidence into the ``[0.0, 1.0]`` range.

    A missing, empty, non-numeric or NaN value means "no confidence was
    expressed", which is ``0.0``. Anything outside the range is clamped.
    """
    try:
        number = float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0
    if not isfinite(number):
        return 0.0
    return max(0.0, min(1.0, number))


def safe_cwe_list(value: Any) -> List[str]:
    """Coerce an untrusted CWE field into a list of identifier strings.

    The field may arrive as one string, a tuple, a bare number or a nested
    list where a list of ids is expected. Anything non-iterable keeps its own
    string form instead of raising, so a single malformed entry cannot abort
    a whole evaluation run.
    """
    if not value:
        return []
    if isinstance(value, str):
        return [value]
    try:
        return [str(c) for c in value if c]
    except TypeError:
        return [str(value)]
