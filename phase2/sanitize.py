"""Sanitize source text before it is shown to the LLM.

Juliet Test Suite samples leak their ground-truth label in three ways:

1. Comments carry the annotation verbatim (``CWE: 190 Integer Overflow`` and
   ``POTENTIAL FLAW: ...``).
2. Identifiers repeat the scenario name, which starts with the CWE number and
   ends with the variant (``CWE190_Integer_Overflow__int_..._45_bad``).
3. The variant markers ``bad`` / ``good`` / ``OMITBAD`` appear as plain
   function and macro names.

Any LLM-only baseline would otherwise read the answer straight out of the
file.  ``sanitize`` removes comments (tree-sitter) and rewrites the leaking
identifiers with stable, non-reversible names.  The mapping is a hash of the
original spelling, so the same identifier is rewritten identically in the
source snippet, the structural evidence and the tool findings.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, Optional

try:
    from tree_sitter import Language, Parser
except ImportError:  # pragma: no cover - tree-sitter is a hard dependency
    Language = None  # type: ignore[assignment]
    Parser = None  # type: ignore[assignment]

try:
    import tree_sitter_c as ts_c
except ImportError:  # pragma: no cover
    ts_c = None

try:
    import tree_sitter_cpp as ts_cpp
except ImportError:  # pragma: no cover
    ts_cpp = None

try:
    import tree_sitter_python as ts_python
except ImportError:  # pragma: no cover
    ts_python = None


# Identifiers that expose the scenario/CWE/variant of a Juliet sample.
_LEAK_RE = re.compile(
    r"""
    \b
    (?:
        CWE\d+_[A-Za-z0-9_]+      # CWE190_Integer_Overflow__int_..._45_bad
      | [Bb]ad[A-Za-z0-9_]*       # bad, badData, badSink, BadSource
      | [Gg]ood[A-Za-z0-9_]*      # good, goodG2BData, GoodSink
      | [Oo]mit[_]?[Bb]ad\b       # OMITBAD / omit_bad
      | [Oo]mit[_]?[Gg]ood\b      # OMITGOOD / omit_good
    )
    \b
    """,
    re.VERBOSE,
)

_PARSERS: Dict[str, Any] = {}
_LANG_BY_EXT = {
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cp": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hh": "cpp",
    ".hpp": "cpp",
    ".hxx": "cpp",
    ".py": "python",
    ".pyw": "python",
}

# Byte -> space, except CR/LF which must survive so line numbering is stable.
_BLANK_TABLE = bytes.maketrans(
    bytes(range(256)),
    bytes(0x20 if i not in (0x0A, 0x0D) else i for i in range(256)),
)


def neutral_name(identifier: str) -> str:
    """Stable, non-reversible replacement for a leaking identifier."""
    digest = hashlib.sha1(identifier.encode("utf-8", "replace")).hexdigest()[:6]
    return f"sym_{digest}"


def sanitize_identifiers(text: str) -> str:
    """Rewrite every label-leaking identifier with its neutral alias."""
    if not text:
        return text
    return _LEAK_RE.sub(lambda m: neutral_name(m.group(0)), text)


def _parser_for(language: str):
    if Parser is None:
        return None
    if language in _PARSERS:
        return _PARSERS[language]
    module = {"c": ts_c, "cpp": ts_cpp, "python": ts_python}.get(language)
    if module is None:
        return None
    parser = Parser(Language(module.language()))
    _PARSERS[language] = parser
    return parser


def strip_comments(text: str, language: Optional[str] = None, *, path: Optional[str] = None) -> str:
    """Remove comments from ``text`` while preserving line numbers."""
    if not text:
        return text
    if language is None and path:
        ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
        language = _LANG_BY_EXT.get(f".{ext}")
    if language is None:
        return text
    parser = _parser_for(language)
    if parser is None:
        return text
    try:
        tree = parser.parse(text.encode("utf-8", "replace"))
    except Exception:  # noqa: BLE001 - never break the pipeline on sanitizing
        return text

    raw = text.encode("utf-8", "replace")
    cuts = []
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type in {"comment", "line_comment", "block_comment"}:
            cuts.append((node.start_byte, node.end_byte))
            continue
        stack.extend(node.children)
    if not cuts:
        return text

    cuts.sort(reverse=True)
    data = raw
    for start, end in cuts:
        # Blank the comment so every following byte offset — and therefore
        # every line number reported by the tools — stays valid.  Newlines
        # inside a block comment are kept: dropping them would pull every
        # later line up and desynchronise the snippet from the file.
        data = data[:start] + data[start:end].translate(_BLANK_TABLE) + data[end:]
    return data.decode("utf-8", "replace")


def sanitize_source(text: str, language: Optional[str] = None, *, path: Optional[str] = None) -> str:
    """Strip label-leaking comments and identifiers from a source snippet."""
    return sanitize_identifiers(strip_comments(text, language, path=path))


def sanitize_value(value: Any, *, identifiers_only: bool = True) -> Any:
    """Recursively sanitize strings inside a JSON-like structure.

    Only identifiers are rewritten here: tool messages and CWE identifiers
    such as ``CWE-120`` must stay untouched (the regex requires an underscore
    after the digits, so ``CWE-190`` is never rewritten).
    """
    if isinstance(value, str):
        return sanitize_identifiers(value)
    if isinstance(value, dict):
        return {k: sanitize_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize_value(v) for v in value]
    return value
