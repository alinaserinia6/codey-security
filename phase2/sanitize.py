"""Sanitize source text before it is shown to the LLM.

Label-bearing benchmark samples leak their ground-truth label in four ways:

1. Comments carry the annotation verbatim (``CWE: 190 Integer Overflow`` and
   ``POTENTIAL FLAW: ...``).
2. Identifiers repeat the scenario name, which starts with the CWE number and
   ends with the variant (``CWE190_Integer_Overflow__int_..._45_bad``,
   ``func1101_bad``).
3. The variant markers ``bad`` / ``good`` / ``OMITBAD`` appear as plain
   function and macro names.
4. The *path* of the sample carries both parts of the label: the ground-truth
   class as a directory (``.../CWE-787/bad/``) and the variant inside the file
   name (``func1147_bad_10ed0bada6d236a0.c``).

Any LLM-only baseline would otherwise read the answer straight out of the
file.  ``sanitize`` removes comments (tree-sitter) and rewrites the leaking
identifiers with stable, non-reversible names.  The mapping is a hash of the
original spelling, so the same identifier is rewritten identically in the
source snippet, the structural evidence and the tool findings.

Leak 4 is handled by :func:`sanitize_paths`, which is deliberately *not* part
of :func:`sanitize_identifiers`: ``CWE-787`` must survive everywhere it is a
legitimate value (a tool's ``cwe`` field, a hypothesis's class, a chain's
label) and only be destroyed where it is a path component.  Keying the rewrite
on path-ness is what lets both hold at once.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List, Optional

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


# Identifiers that expose the scenario/CWE/variant of a labelled sample.
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


# ---------------------------------------------------------------------------
# Path sanitizing
# ---------------------------------------------------------------------------
#: Extensions that mark a string as a source path rather than prose.
_SOURCE_EXTS = frozenset({
    ".c", ".h", ".cc", ".cp", ".cpp", ".cxx", ".hh", ".hpp", ".hxx",
    ".py", ".pyw", ".java", ".go", ".rs", ".js", ".jsx", ".ts", ".tsx",
    ".rb", ".php", ".cs", ".kt", ".swift", ".m", ".mm",
})

#: A directory component that is nothing but the ground-truth class, e.g. the
#: ``CWE-787`` of ``.../function_level/c/CWE-787/bad/``.  The underscore form
#: is already caught by :data:`_LEAK_RE`; this covers the hyphenated one.
_CLASS_DIR_RE = re.compile(r"^CWE[-_]?\d{1,6}$", re.IGNORECASE)

#: A variant directory component.  ``bad``/``good`` are caught by
#: :data:`_LEAK_RE`; the rest name the label the same way.
_VARIANT_DIR_RE = re.compile(
    r"^(?:vuln|vulnerable|patched|fixed|safe|benign|secure|clean|omitted)$",
    re.IGNORECASE,
)

#: ``":<digits>"`` at the end of a location reference.
_LINE_SUFFIX_RE = re.compile(r":(\d{1,9})$")

#: The leak tokens again, but unanchored.  ``_LEAK_RE`` needs a word boundary
#: on both sides, and a sample file name defeats that on the left: in
#: ``func1147_bad_10ed0bada6d236a0.c`` the character before ``bad`` is ``_``,
#: which is itself a word character, so there is no boundary and the variant
#: marker survives.  Deciding on a file *stem* is a different question from
#: deciding on a standalone identifier, so it gets its own pattern.
_LEAK_ANYWHERE_RE = re.compile(
    r"CWE[-_]?\d{1,6}|[Bb]ad|[Gg]ood|[Oo]mit[_]?[Bb]ad|[Oo]mit[_]?[Gg]ood"
)


def _strip_line_suffix(value: str) -> "tuple[str, str]":
    """Split ``"file:line"`` into ``("file", ":line")``.

    The line has to survive path scrubbing: the report and the matcher both
    use it, and it is the one part of a location that carries no label.  The
    head only counts as a path when it has a directory part or a source
    extension, so that prose like ``"note:12"`` is left alone.
    """
    match = _LINE_SUFFIX_RE.search(value)
    if not match:
        return value, ""
    head = value[: match.start()]
    if "/" in head or "\\" in head or _has_source_ext(head):
        return head, match.group(0)
    return value, ""


def _has_source_ext(value: str) -> bool:
    stem, dot, ext = value.replace("\\", "/").rpartition("/")[-1].rpartition(".")
    return bool(dot) and ("." + ext).lower() in _SOURCE_EXTS


def looks_like_path(value: str) -> bool:
    """Whether ``value`` is a source path (or a ``path:line`` reference).

    Used instead of the field name because a leak reaches an agent through
    whichever key happens to carry it: ``packet["file"]``,
    ``dataflow_chains[].file``, a tool message quoting a location, or the
    ``source_location`` the model is asked to echo back.  A bare file name
    counts, because that is the form a model writes back for ``source_location``.
    """
    if not value or len(value) > 4096:
        return False
    head, _ = _strip_line_suffix(value)
    return _has_source_ext(head)


def sanitize_path(value: str) -> str:
    """Rewrite the label-bearing components of a source path.

    Keeps the shape of the path -- directories and the file extension -- so the
    agent can still tell a C file from a Python one, and replaces everything
    that encodes the answer: the class directory (``CWE-787``), the variant
    directory (``bad``) and the file name (``func1147_bad_10ed0bada6d236a0.c``).
    A trailing ``:line`` is preserved, because the report needs it.
    """
    if not isinstance(value, str) or not value:
        return value

    location, line_suffix = _strip_line_suffix(value)
    normalized = location.replace("\\", "/")
    drive = ""
    if re.match(r"^[A-Za-z]:", normalized):
        drive, normalized = normalized[:2], normalized[2:]

    parts = normalized.split("/")
    out: List[str] = []
    for index, part in enumerate(parts):
        last = index == len(parts) - 1
        stem, dot, ext = part.rpartition(".")
        has_ext = bool(dot) and ("." + ext).lower() in _SOURCE_EXTS

        if not part:
            out.append(part)
        elif _CLASS_DIR_RE.match(part) or _VARIANT_DIR_RE.match(part):
            out.append(neutral_name(part))
        elif _LEAK_RE.fullmatch(part):
            out.append(neutral_name(part))
        elif last and has_ext and _LEAK_ANYWHERE_RE.search(stem):
            # ``func1147_bad_10ed0bada6d236a0.c``: the variant marker survives
            # :func:`sanitize_identifiers` because the preceding ``_`` is a word
            # character and defeats the ``\b`` anchor, and the numeric sample id
            # ties the file back to the ground truth.  The whole stem goes.
            out.append(f"{neutral_name(stem)}{dot}{ext}")
        else:
            out.append(part)

    joined = "/".join(out)
    return (f"{drive}{joined}" if drive else joined) + line_suffix


def sanitize_value(value: Any, *, identifiers_only: bool = True) -> Any:
    """Recursively sanitize strings inside a JSON-like structure.

    Two passes, because the two kinds of leak need opposite treatment.
    Identifiers are rewritten everywhere: ``CWE190_..._bad`` becomes
    ``sym_...`` in the snippet, the structural index and the tool messages
    alike.  Paths are rewritten only where they are paths, so ``CWE-190`` in a
    tool's ``cwe`` field, in a hypothesis or in a chain label stays legible --
    that spelling carries the evidence, and only its use as a *directory* is
    the answer.
    """
    if isinstance(value, str):
        return sanitize_identifiers(value)
    if isinstance(value, dict):
        return {k: sanitize_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize_value(v) for v in value]
    return value


def sanitize_packet(value: Any) -> Any:
    """:func:`sanitize_value` plus the path pass, in that order.

    The order matters: identifiers are rewritten first so that a leaking
    ``bad`` *directory* is already a ``sym_`` token by the time the path pass
    runs, and both passes together cover a path component that leaks for
    either reason.
    """
    return _sanitize_paths(sanitize_value(value))


def _sanitize_paths(value: Any) -> Any:
    if isinstance(value, str):
        return sanitize_path(value) if looks_like_path(value) else value
    if isinstance(value, dict):
        return {k: _sanitize_paths(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize_paths(v) for v in value]
    return value
