"""Intra-procedural source-to-sink dataflow evidence.

The proposal requires that a vulnerability is only reported when an explicit
source-to-sink path can be shown, so this module recovers those paths from the
Tree-sitter index rather than leaving the claim to the model.

The analysis is deliberately intra-procedural and flow-insensitive:

* a *source* is a call or reference that matches a known untrusted-input
  pattern, and it taints whatever name is bound to its result;
* an *assignment* copies taint from the names it reads to the names it writes,
  so ``cmd = "ls " + name`` keeps the taint of ``name``;
* a *sink* is a call matching a known dangerous pattern that reads a tainted
  name, which yields a chain with the exact statements that produced it.

This is weaker than a points-to/alias analysis, on purpose. A conservative
engine would under-report; an unsound one would hand the verifier agent a
fabricated path, which is exactly the hallucination the design exists to
prevent. Chains are therefore emitted as *candidates* carrying their
supporting statements, and the verifier decides whether the path is real.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

# --------------------------------------------------------------------------
# Source and sink vocabulary
# --------------------------------------------------------------------------
# Patterns are matched against the dotted head of an expression, so
# "os.environ.get" matches "os.environ.get(\"PATH\")" and "sys.argv" matches
# "sys.argv[1]". The C side has no owner qualification, which is correct:
# strcpy is strcpy.

SOURCE_PATTERNS: Dict[str, Set[str]] = {
    "c": {
        "argv", "argc", "getenv", "read", "fgets", "fread", "recv", "recvfrom",
        "getline", "scanf", "sscanf", "fscanf", "gets", "getpass", "gethostname",
        "getcwd", "fopen", "fscanf", "readlink", "basename", "dirname",
    },
    "python": {
        "input", "raw_input",
        "sys.stdin.read", "sys.stdin.readline", "sys.stdin.readlines", "sys.argv",
        "os.environ.get", "os.getenv", "os.environ",
        "getpass.getpass",
        "request.args.get", "request.form.get", "request.values.get",
        "request.cookies.get", "request.headers.get", "request.get_json",
        "request.get_data", "request.data", "request.args", "request.form",
        "request.values", "request.json", "request.body",
        "flask.request.args.get", "flask.request.form.get",
        "flask.request.get_json", "flask.request.get_data", "flask.request.data",
        "django.http.request.HttpRequest.GET", "socket.recv", "socket.recvfrom",
        "urllib.request.urlopen", "read", "readline", "readlines",
    },
}

# Calls that neutralise taint rather than propagating it. Dataflow semantics
# matter here: ast.literal_eval(attacker_text) cannot return attacker code, and
# os.path.basename(attacker_path) cannot escape its directory, so a value that
# has passed through one of these is no longer attacker-controlled. A tracker
# that keeps propagating through them reports every correctly repaired variant
# as a finding.
SANITIZERS: Set[str] = {
    "ast.literal_eval", "literal_eval",
    "os.path.basename", "basename", "secure_filename", "werkzeug.utils.secure_filename",
    "shlex.quote", "shlex.split", "quote",
    "urllib.parse.quote", "urlencode",
    "re.escape", "escape",
    "yaml.safe_load", "json.loads", "json.load",
    "int", "float", "bool", "sanitize", "sanitise", "validate", "allowlist",
    "hashlib.sha256", "md5",
}

SINK_PATTERNS: Dict[str, Dict[str, List[str]]] = {
    "c": {
        "command_injection": [
            "system", "popen", "execl", "execlp", "execle", "execv", "execvp",
            "execlpe", "posix_spawn",
        ],
        "code_injection": ["dlopen", "dlsym"],
        "buffer_overflow": [
            "strcpy", "strcat", "sprintf", "vsprintf", "gets", "memcpy",
            "memmove", "wcscpy", "wcscat", "lstrcpy", "lstrcat", "bcopy",
            "strncpy", "strncat", "fgets",
        ],
        "path_traversal": ["fopen", "open", "unlink", "remove", "rename"],
    },
    "python": {
        "command_injection": [
            "os.system", "os.popen", "os.execv", "os.execve", "os.spawnl",
            "subprocess.call", "subprocess.run", "subprocess.Popen",
            "subprocess.check_output", "subprocess.check_call",
            "subprocess.getoutput", "commands.getoutput", "pty.spawn",
        ],
        "code_injection": ["eval", "exec", "compile"],
        "template_injection": [
            "render_template_string", "Template", "from_string", "Environment",
        ],
        "unsafe_deserialization": [
            "yaml.load", "yaml.unsafe_load", "yaml.full_load", "yaml.unsafe_load_all",
            "pickle.loads", "pickle.load", "marshal.loads", "marshal.load",
            "shelve.open", "dill.loads", "jsonpickle.decode", "np.load",
        ],
        "sql_injection": [
            "cursor.execute", "execute", "executemany", "executebatch", "raw",
        ],
        "path_traversal": [
            "open", "os.remove", "os.unlink", "shutil.rmtree", "send_file",
        ],
    },
}

# Categories that are dangerous only when the attacker can reach the argument.
# Everything else is still surfaced, but flagged as lacking a proven path.
TAINT_SENSITIVE_CATEGORIES = {
    "command_injection",
    "code_injection",
    "template_injection",
    "unsafe_deserialization",
    "sql_injection",
    "path_traversal",
    "buffer_overflow",
}

# Wrappers that forward taint from their argument to their result.
TAINT_PROPAGATORS = {
    "str", "bytes", "format", "join", "strip", "lstrip", "rstrip", "lower",
    "upper", "replace", "encode", "decode", "split", "trim", "substr",
    "formatString", "copy", "deepcopy", "list", "dict",
}

CWE_FOR_CATEGORY = {
    "command_injection": "CWE-78",
    "code_injection": "CWE-94",
    "template_injection": "CWE-1336",
    "unsafe_deserialization": "CWE-502",
    "sql_injection": "CWE-89",
    "path_traversal": "CWE-22",
    "buffer_overflow": "CWE-120",
}

# Sinks that take an explicit length, so a bounded copy can be recognised and
# discounted instead of being reported as a path.
BOUNDED_COPY_SINKS = {
    "strncpy", "strncat", "memcpy", "memmove", "bcopy", "lstrncpy", "lstrncat",
    "wcscpy", "wcsncpy", "wcscat", "wcsncat", "snprintf", "fgets", "read",
}

# Sinks whose final argument is the destination size.
BOUNDED_COPY_SIZE_INDEX = {
    "strncpy": 2, "strncat": 2, "wcscpy": 2, "wcsncpy": 2, "wcscat": 2,
    "wcsncat": 2, "memcpy": 2, "memmove": 2, "bcopy": 2, "lstrncpy": 2,
    "lstrncat": 2, "snprintf": 1, "fgets": 1, "read": 1,
}

# Juliet's cross-file input buffers. A global matching this is filled from a
# data stream in another translation unit, which is invisible intra-procedurally.
_GLOBAL_INPUT_RE = re.compile(
    r"(?:^|_)(bad|good)?_?g2bdata$|data$|input$|buffer$", re.IGNORECASE
)

_NUMERIC_RE = re.compile(r"\d")

# strlen/wcslen/strnlen style length calls, used to recognise a bound that is
# derived from the copied data rather than from a fixed constant.
_LENGTH_CALL_RE = re.compile(r"\b\w*strn?len\s*\(")

# Unbounded copies: dangerous only if the destination is not sized to the data.
UNBOUNDED_COPY_SINKS = {
    "strcpy", "strcat", "sprintf", "vsprintf", "gets", "wcscpy", "wcscat",
    "lstrcpy", "lstrcat",
}

# Python command sinks that are safe when the command is an argument list
# rather than a string handed to a shell.
_SHELL_SINKS = {
    "os.system", "os.popen", "subprocess.call", "subprocess.run",
    "subprocess.Popen", "subprocess.check_output", "subprocess.check_call",
    "commands.getoutput",
}

_SANITIZER_RE = re.compile(
    r"\b(?:" + "|".join(sorted((re.escape(s) for s in SANITIZERS), key=len, reverse=True)) + r")\s*\("
)


def _strip_sanitized(expression: str) -> str:
    """Blank out sanitizer call arguments so their names stop counting as tainted.

    ``os.path.basename(name)`` must not keep ``name`` reachable, otherwise a
    repaired variant reads as tainted and is reported anyway. Only the argument
    list of a known sanitizer is removed; the call head itself stays so nested
    expressions are still visible.
    """
    text = expression or ""
    out: List[str] = []
    index = 0
    while True:
        match = _SANITIZER_RE.search(text, index)
        if match is None:
            out.append(text[index:])
            return "".join(out)
        out.append(text[index : match.start()])
        depth = 0
        cursor = match.end() - 1  # the opening parenthesis
        while cursor < len(text):
            if text[cursor] == "(":
                depth += 1
            elif text[cursor] == ")":
                depth -= 1
                if depth == 0:
                    cursor += 1
                    break
            cursor += 1
        out.append(" __sanitized__ ")
        index = cursor

_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_HEAD_RE = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*"
    r"(?:\s*(?:\.|::)\s*[A-Za-z_][A-Za-z0-9_]*)*"
)
# A leading C cast, as in "(char *)calloc(...)", hides the callee from the
# head regex because the expression does not start with an identifier.
_CAST_RE = re.compile(r"^\(\s*(?:const\s+)?[A-Za-z_][A-Za-z0-9_]*\s*\*+\s*\)")
_KEYWORDS = {
    # Statement keywords that would otherwise look like dataflow names. "in"
    # is deliberately absent: it is a common C parameter name, and dropping it
    # would hide a real source-to-sink path.
    "if", "else", "elif", "while", "for", "return", "and", "or", "not",
    "def", "class", "with", "as", "try", "except", "int", "str", "bool",
    "True", "False", "None", "self",
}


@dataclass
class TaintStep:
    """One statement that introduces, moves or delivers taint."""

    line: int
    kind: str  # "source" | "propagate" | "sink"
    expression: str
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TaintChain:
    """A candidate source-to-sink path inside one function."""

    file: str
    function: str
    category: str
    cwe: str
    source_expression: str
    sink_expression: str
    source_line: int
    sink_line: int
    steps: List[TaintStep] = field(default_factory=list)
    propagated: bool = False
    intra_procedural: bool = True
    taint_origin: str = ""
    mitigated: bool = False
    mitigation: str = ""
    mitigation_rule: str = ""

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["steps"] = [step.to_dict() for step in self.steps]
        payload["chain"] = self.render()
        return payload

    def render(self) -> str:
        """Human-readable ``source -> ... -> sink`` path for the evidence packet."""
        if not self.source_expression:
            return (
                f"SINK {self.sink_expression} (line {self.sink_line}) "
                "- no source-to-sink path found"
            )
        parts = [f"source {self.source_expression} (line {self.source_line})"]
        for step in self.steps:
            if step.kind == "propagate":
                parts.append(f"-> {step.expression} (line {step.line})")
        parts.append(f"-> SINK {self.sink_expression} (line {self.sink_line})")
        rendered = "  ".join(parts)
        if self.taint_origin:
            rendered += f"  [origin: {self.taint_origin}]"
        if self.mitigated:
            rendered += f"  [mitigated: {self.mitigation}]"
        return rendered


def _strip_casts(expression: str) -> str:
    """Remove leading C casts so the callee is visible to the head matcher."""
    result = (expression or "").strip()
    while True:
        stripped = _CAST_RE.sub("", result).strip()
        if stripped == result:
            return result
        result = stripped


def _call_head(expression: str) -> str:
    """The dotted callee prefix of an expression.

    ``request.args.get("q")`` -> ``request.args.get``; ``sys.argv[1]`` ->
    ``sys.argv``; ``"ls " + name`` -> ``""`` because a concatenation is not a
    call and must not be mistaken for one. A leading cast is dropped first, so
    ``(char *)calloc(n, 1)`` resolves to ``calloc``.
    """
    match = _HEAD_RE.match(_strip_casts(expression))
    return re.sub(r"\s+", "", match.group(0)) if match else ""


def _match_patterns(expression: str, patterns: Iterable[str]) -> Optional[str]:
    """Return the pattern matching ``expression``, longest pattern first.

    Longest-first is required for overlapping entries: ``os.environ.get`` must
    win over ``get``, and ``yaml.load`` over ``load``. Both ``.`` and ``::`` are
    accepted as scope separators, so a C++ ``std::strcpy`` matches ``strcpy``
    the same way a C ``strcpy`` does.
    """
    head = _call_head(expression)
    if not head:
        return None
    for pattern in sorted(patterns, key=len, reverse=True):
        if head == pattern:
            return pattern
        if head.endswith(f".{pattern}") or head.endswith(f"::{pattern}"):
            return pattern
    return None


def _names_in(expression: str) -> Set[str]:
    """Identifiers mentioned in an expression, minus language keywords."""
    return {
        name for name in _IDENT_RE.findall(expression or "") if name not in _KEYWORDS
    }


def _parameter_names(function: Dict[str, Any]) -> Set[str]:
    """Parameter names of a function, used as a taint origin for C.

    A Juliet-style test case is vulnerable because the harness passes attacker
    data into the parameter, which is invisible to an intra-procedural
    analysis, so parameters are treated as untrusted and the resulting chains
    are labelled with ``taint_origin="parameter"`` rather than presented as a
    proven external source.
    """
    return _names_in(str(function.get("parameters", "") or ""))


#: Tree-sitter reports C++ under a language of its own, but every source and
#: sink in the C table applies to it unchanged, and a qualified or templated
#: callee is matched by suffix anyway (`Foo::copy` matches `copy`). Without this
#: mapping a C++ file produced no chains at all, which the chain gate would then
#: read as evidence that the file was safe.
_TAINT_LANGUAGE_ALIASES = {"cpp": "c"}


def taint_language(language: str) -> str:
    """Map a Tree-sitter language onto the pattern table that covers it."""
    return _TAINT_LANGUAGE_ALIASES.get(language, language)


class TaintTracker:
    """Builds candidate source-to-sink chains from a structural analysis."""

    def __init__(self, *, max_steps: int = 12) -> None:
        self.max_steps = max_steps

    def analyze(
        self,
        structure: Dict[str, Any],
        *,
        file: str = "",
        functions: Optional[Sequence[Dict[str, Any]]] = None,
    ) -> List[Dict[str, Any]]:
        """Return one record per detected source-to-sink chain."""
        language = taint_language(structure.get("language", ""))
        if language not in SOURCE_PATTERNS:
            return []

        records: List[Dict[str, Any]] = []
        for function in functions or structure.get("functions", []):
            records.extend(self._analyze_function(function, structure, language))
        records.sort(key=lambda record: (record["source_line"], record["sink_line"]))
        return records

    # -- per-function ----------------------------------------------------
    def _analyze_function(
        self, function: Dict[str, Any], structure: Dict[str, Any], language: str
    ) -> List[Dict[str, Any]]:
        start = function.get("start_line") or 1
        end = function.get("end_line") or start
        name = str(function.get("name", "<anonymous>"))

        calls = self._in_range(structure.get("calls", []), start, end)
        if not calls:
            return []
        assignments = self._in_range(structure.get("assignments", []), start, end)
        references = self._in_range(structure.get("references", []), start, end)

        sources = SOURCE_PATTERNS[language]
        sink_categories = SINK_PATTERNS[language]
        parameters = _parameter_names(function)

        # tainted[name] is the *full* path from the original source to that
        # name, so a chain can always be walked back to where taint began.
        tainted: Dict[str, List[TaintStep]] = {}
        origins: Dict[str, str] = {}
        # allocations[name] is the size expression a buffer was allocated with,
        # which is how a correctly sized destination is recognised.
        allocations: Dict[str, str] = {}
        chains: List[TaintChain] = []

        source_reads = self._source_reads(calls, references, sources, parameters)
        source_reads.extend(
            self._global_source_reads(structure, calls, sources)
        )

        for line in sorted(
            {int(c["line"]) for c in calls}
            | {int(a["line"]) for a in assignments}
            | {int(r["line"]) for r in source_reads if r["line"] != -1}
        ):
            self._apply_sources(
                line, source_reads, assignments, tainted, origins
            )
            self._apply_assignments(
                line, assignments, sources, tainted, origins, allocations
            )
            self._apply_propagators(line, calls, assignments, tainted, origins)
            chains.extend(
                self._apply_sinks(
                    line, calls, sink_categories, tainted, origins,
                    structure, language, name, source_reads, allocations,
                )
            )

        return [chain.to_dict() for chain in chains]

    # -- sources ---------------------------------------------------------
    def _source_reads(
        self,
        calls: Sequence[Dict[str, Any]],
        references: Sequence[Dict[str, Any]],
        sources: Set[str],
        parameters: Set[str],
    ) -> List[Dict[str, Any]]:
        """Untrusted reads on each line, from calls, references and parameters.

        Calls and references overlap heavily: the callee ``request.args.get``
        appears both as a call and as the attribute nodes underneath it. Only
        one of them is kept per line so a single source is not counted twice.
        """
        reads: List[Dict[str, Any]] = []
        seen: Set[tuple] = set()

        for call in calls:
            head = str(call.get("name", ""))
            pattern = _match_patterns(head, sources)
            if pattern is None:
                continue
            key = (int(call.get("line") or 0), pattern)
            if key in seen:
                continue
            seen.add(key)
            reads.append(
                {
                    "line": int(call.get("line") or 0),
                    "expression": str(call.get("expression", head)),
                    "pattern": pattern,
                    "origin": "external-source",
                }
            )

        for reference in references:
            text = str(reference.get("text", ""))
            pattern = _match_patterns(text, sources)
            if pattern is None:
                continue
            key = (int(reference.get("line") or 0), pattern)
            if key in seen:
                continue
            seen.add(key)
            reads.append(
                {
                    "line": int(reference.get("line") or 0),
                    "expression": text,
                    "pattern": pattern,
                    "origin": "external-source",
                }
            )

        for parameter in sorted(parameters):
            reads.append(
                {
                    "line": -1,  # available everywhere in the body
                    "expression": f"parameter {parameter}",
                    "pattern": "parameter",
                    "origin": "parameter",
                    "name": parameter,
                }
            )
        return reads

    def _global_source_reads(
        self,
        structure: Dict[str, Any],
        calls: Sequence[Dict[str, Any]],
        sources: Set[str],
    ) -> List[Dict[str, Any]]:
        """File-scope input buffers that stand in for a cross-file source.

        Juliet passes attacker data between translation units through a global
        (``extern int * ..._badData``) that is filled from a data stream in
        another file, so no in-file source call exists. Treating such a global
        as a source recovers those cases; a global that is written by a source
        call in this same file is treated the same way, which is why the write
        is looked up rather than only the name shape.
        """
        globals_found = structure.get("globals", [])
        if not globals_found:
            return []

        written_by_source: Set[str] = set()
        for call in calls:
            if _match_patterns(str(call.get("name", "")), sources) is None:
                continue
            for name in _names_in(str(call.get("expression", ""))):
                written_by_source.add(name)

        reads: List[Dict[str, Any]] = []
        for entry in globals_found:
            for name in entry.get("names", []):
                if name not in written_by_source and not _GLOBAL_INPUT_RE.search(name):
                    continue
                reads.append(
                    {
                        # line -1 makes the buffer taint available for the whole
                        # body, like a parameter, since the real write happens
                        # in another translation unit.
                        "line": -1,
                        "expression": f"global {name}",
                        "pattern": "global-input-buffer",
                        "origin": "global-source",
                        "name": name,
                    }
                )
        return reads

    def _apply_sources(
        self,
        line: int,
        source_reads: Sequence[Dict[str, Any]],
        assignments: Sequence[Dict[str, Any]],
        tainted: Dict[str, List[TaintStep]],
        origins: Dict[str, str],
    ) -> None:
        for read in source_reads:
            if read["line"] not in (line, -1):
                continue
            if read.get("name"):
                # A parameter taints its own name without a binding statement.
                # A concrete external source on the same line is a stronger
                # claim, so it is never downgraded to "parameter".
                if read["origin"] == "parameter" and origins.get(read["name"]) == "external-source":
                    continue
                tainted[read["name"]] = [
                    TaintStep(
                        line=line,
                        kind="source",
                        expression=read["expression"],
                        detail=read["pattern"],
                    )
                ]
                origins[read["name"]] = read["origin"]
                continue
            for target in self._bound_names(assignments, line):
                tainted[target] = [
                    TaintStep(
                        line=line,
                        kind="source",
                        expression=read["expression"],
                        detail=read["pattern"],
                    )
                ]
                origins[target] = read["origin"]

    def _apply_assignments(
        self,
        line: int,
        assignments: Sequence[Dict[str, Any]],
        sources: Set[str],
        tainted: Dict[str, List[TaintStep]],
        origins: Dict[str, str],
        allocations: Dict[str, str],
    ) -> None:
        for assignment in assignments:
            if int(assignment.get("line") or 0) != line:
                continue
            targets = [t for t in assignment.get("targets", []) if t]
            value = str(assignment.get("value", ""))
            if not targets or not value:
                continue

            allocated = self._allocation_size(value)
            if allocated is not None:
                for target in targets:
                    allocations[target] = allocated

            pattern = _match_patterns(value, sources)
            if pattern is not None:
                step = TaintStep(line=line, kind="source", expression=value, detail=pattern)
                for target in targets:
                    tainted[target] = [step]
                    origins[target] = "external-source"
                continue

            path = self._longest_path(value, tainted)
            if path is None:
                continue
            step = TaintStep(
                line=line,
                kind="propagate",
                expression=f"{' = '.join(targets)} <- {value}",
                detail="assignment",
            )
            inherited_origin = self._origin_of(value, origins)
            for target in targets:
                tainted[target] = path + [step]
                origins[target] = inherited_origin

    def _apply_propagators(
        self,
        line: int,
        calls: Sequence[Dict[str, Any]],
        assignments: Sequence[Dict[str, Any]],
        tainted: Dict[str, List[TaintStep]],
        origins: Dict[str, str],
    ) -> None:
        for call in calls:
            if int(call.get("line") or 0) != line:
                continue
            callee = str(call.get("name", ""))
            if callee.split(".")[-1] not in TAINT_PROPAGATORS:
                continue
            expression = str(call.get("expression", ""))
            path = self._longest_path(expression, tainted)
            if path is None:
                continue
            step = TaintStep(
                line=line, kind="propagate", expression=expression, detail=callee
            )
            inherited_origin = self._origin_of(expression, origins)
            for target in self._bound_names(assignments, line):
                tainted[target] = path + [step]
                origins[target] = inherited_origin

    # -- sinks -----------------------------------------------------------
    def _apply_sinks(
        self,
        line: int,
        calls: Sequence[Dict[str, Any]],
        sink_categories: Dict[str, List[str]],
        tainted: Dict[str, List[TaintStep]],
        origins: Dict[str, str],
        structure: Dict[str, Any],
        language: str,
        function_name: str,
        source_reads: Sequence[Dict[str, Any]] = (),
        allocations: Optional[Dict[str, str]] = None,
    ) -> List[TaintChain]:
        chains: List[TaintChain] = []
        for call in calls:
            if int(call.get("line") or 0) != line:
                continue
            callee = str(call.get("name", ""))
            category = self._sink_category(callee, sink_categories)
            if category is None:
                continue
            expression = str(call.get("expression", ""))

            # A source read nested inside the sink argument needs no binding
            # step: os.system("ls " + request.args.get("q")) is already a
            # complete path. It is checked before the taint map because a
            # concrete external source is a stronger claim than the parameter
            # fallback that would otherwise match on the same line.
            inline = self._inline_source(expression, line, source_reads, callee)
            if inline is not None:
                step = TaintStep(
                    line=line, kind="source", expression=inline["expression"],
                    detail=inline["pattern"],
                )
                chains.append(
                    self._chain(
                        structure, function_name, category, language, expression,
                        line, [step], [], "external-source",
                    )
                )
                continue

            path = self._longest_path(expression, tainted)
            if path is not None:
                steps = [step for step in path if step.line != line or step.kind == "source"]
                chain = self._chain(
                    structure, function_name, category, language, expression,
                    line, path, steps, self._origin_of(expression, origins),
                )
                rule, mitigation = self._mitigation(
                    callee, expression, tainted, allocations or {}
                )
                if rule:
                    chain.mitigated = True
                    chain.mitigation_rule = rule
                    chain.mitigation = mitigation
                chains.append(chain)
                continue

            if category not in TAINT_SENSITIVE_CATEGORIES:
                continue
            chains.append(
                TaintChain(
                    file=str(structure.get("path", "")),
                    function=function_name,
                    category=category,
                    cwe=CWE_FOR_CATEGORY.get(category, "CWE-682"),
                    source_expression="",
                    sink_expression=expression,
                    source_line=line,
                    sink_line=line,
                    steps=[],
                    propagated=False,
                )
            )
        return chains

    @classmethod
    def _inline_source(
        cls,
        expression: str,
        line: int,
        source_reads: Sequence[Dict[str, Any]],
        sink_callee: str,
    ) -> Optional[Dict[str, Any]]:
        """An external source read appearing inside this sink's arguments.

        The match is restricted to the argument list. A plain substring search
        over the whole call text would also fire on text that comes *after* the
        sink closes, which is how ``open(join(base, safe)).read()`` ends up
        looking like ``read`` flowing into ``open``.
        """
        arguments = " ".join(cls._split_arguments(expression))
        if not arguments:
            return None
        for read in source_reads:
            if read.get("origin") != "external-source" or read["line"] != line:
                continue
            text = read["expression"]
            if not text or text == sink_callee:
                continue
            if text in arguments:
                return read
        return None

    # -- chain construction ----------------------------------------------
    def _chain(
        self,
        structure: Dict[str, Any],
        function_name: str,
        category: str,
        language: str,
        expression: str,
        line: int,
        path: Sequence[TaintStep],
        steps: Sequence[TaintStep],
        origin: str,
    ) -> TaintChain:
        first = path[0]
        return TaintChain(
            file=str(structure.get("path", "")),
            function=function_name,
            category=category,
            cwe=CWE_FOR_CATEGORY.get(category, "CWE-682"),
            source_expression=first.expression,
            sink_expression=expression,
            source_line=first.line,
            sink_line=line,
            steps=list(steps)[: self.max_steps],
            propagated=any(step.kind == "propagate" for step in steps),
            taint_origin=origin,
        )

    # -- helpers ---------------------------------------------------------
    @staticmethod
    def _in_range(items: Sequence[Dict[str, Any]], start: int, end: int) -> List[Dict[str, Any]]:
        return [item for item in items if start <= (item.get("line") or 0) <= end]

    @staticmethod
    def _bound_names(assignments: Sequence[Dict[str, Any]], line: int) -> List[str]:
        """Names bound by an assignment on this line."""
        names: List[str] = []
        for assignment in assignments:
            if int(assignment.get("line") or 0) != line:
                continue
            if not str(assignment.get("value", "")).strip():
                continue
            names.extend(t for t in assignment.get("targets", []) if t)
        return names

    @staticmethod
    def _longest_path(
        expression: str, tainted: Dict[str, List[TaintStep]]
    ) -> Optional[List[TaintStep]]:
        """The deepest existing taint path among the names this expression reads.

        Sanitizer arguments are excluded, so a value that has been through
        ``os.path.basename`` or ``ast.literal_eval`` no longer counts as
        attacker-controlled.
        """
        best: Optional[List[TaintStep]] = None
        for name in _names_in(_strip_sanitized(expression)):
            path = tainted.get(name)
            if path and (best is None or len(path) > len(best)):
                best = path
        return best

    @staticmethod
    def _origin_of(expression: str, origins: Dict[str, str]) -> str:
        for name in _names_in(_strip_sanitized(expression)):
            if name in origins:
                return origins[name]
        return ""

    @staticmethod
    def _python_mitigation(callee: str, args: List[str]) -> tuple:
        """Safe calling conventions for the Python sinks.

        Two of these carry most of the weight. An argument list instead of a
        string means no shell is involved, so injection through the argument
        is not possible however the argument was built. A second argument to
        ``execute`` means the query is parameterised, so the tainted value is
        bound as data rather than parsed as SQL.
        """
        if callee in _SHELL_SINKS and args:
            first = args[0].strip()
            if first.startswith("["):
                return (
                    "argument-list",
                    f"{callee} called with an argument list, so no shell parses it",
                )
            lowered = " ".join(args).lower()
            if "shell=false" in lowered:
                return (
                    "no-shell",
                    f"{callee} called with shell=False, so no shell parses the argument",
                )
        if callee in {"cursor.execute", "execute", "executemany", "session.execute"}:
            if len(args) >= 2:
                return (
                    "parameterised-query",
                    f"{callee} called with bound parameters, so the value is not parsed as SQL",
                )
        if callee in {"yaml.load", "yaml.full_load"} and len(args) >= 2:
            if args[1].strip() in {"Loader=yaml.SafeLoader", "SafeLoader"}:
                return "safe-loader", f"{callee} called with a safe loader"
        return ("", "")

    @staticmethod
    def _allocation_size(value: str) -> Optional[str]:
        """The size expression of a ``malloc``/``calloc`` bound to a name.

        ``char *dest = (char *)calloc(strlen(data) + 1, 1)`` sizes the
        destination from the tainted data, so a later ``strcpy(dest, data)``
        cannot overrun and is not a finding.
        """
        head = _call_head(value)
        if head.split(".")[-1] not in {"malloc", "calloc", "realloc", "new"}:
            return None
        args = TaintTracker._split_arguments(_strip_casts(value))
        if not args:
            return None
        return args[0] if head.split(".")[-1] != "calloc" else " ".join(args)

    @staticmethod
    def _split_arguments(expression: str) -> List[str]:
        """Split a call's argument list on top-level commas."""
        head = _call_head(expression)
        start = expression.find("(", len(head))
        if start == -1:
            return []
        depth = 0
        args: List[str] = []
        current = ""
        for char in expression[start:]:
            if char in "([{":
                depth += 1
                if depth == 1:
                    continue
            elif char in ")]}":
                depth -= 1
                if depth == 0:
                    args.append(current.strip())
                    break
            if char == "," and depth == 1:
                args.append(current.strip())
                current = ""
                continue
            current += char
        return args

    @classmethod
    def _mitigation(
        cls,
        callee: str,
        expression: str,
        tainted: Dict[str, List[TaintStep]],
        allocations: Dict[str, str],
    ) -> tuple:
        """Describe an explicit bound that limits this path, if there is one.

        This is the main false-positive filter. A Juliet ``_good`` variant is
        written so the copy *is* bounded, so reporting the same source-to-sink
        shape as in the ``_bad`` variant is exactly the noise the proposal
        targets. Three shapes are recognised:

        * a size argument containing a literal and no tainted name, e.g.
          ``memcpy(d, s, 100 * sizeof(int))``;
        * a size argument derived from ``strlen`` of the copied data;
        * a destination that was allocated from the tainted data's length,
          e.g. ``calloc(strlen(data) + 1, 1)``.
        """
        short = callee.split(".")[-1]
        args = cls._split_arguments(expression)

        # (0) Python: the sink is called in a form that is already safe.
        python_mitigation = cls._python_mitigation(callee, args)
        if python_mitigation[0]:
            return python_mitigation

        # (3) destination sized to the data, for unbounded copies.
        if short in UNBOUNDED_COPY_SINKS and args:
            destination = args[0].split()[-1] if args[0] else ""
            size = allocations.get(destination)
            if size and _names_in(size) & set(tainted):
                return "sized-destination", f"destination {destination} allocated as {size.strip()}"

        if short not in BOUNDED_COPY_SINKS:
            return ("", "")
        index = BOUNDED_COPY_SIZE_INDEX.get(short)
        if index is None or len(args) <= index:
            return ("", "")
        size = args[index]
        if not size:
            return ("", "")
        # (2) a bound derived from the length of the copied data. This is
        # checked first because it is the more specific claim, and the generic
        # numeric rule below would otherwise also match expressions like
        # "(strlen(src) + 1) * sizeof(char)".
        if _LENGTH_CALL_RE.search(size):
            return "length-bounded", f"length bounded by {size.strip()}"
        # (1) a literal bound that does not itself depend on tainted data.
        if _NUMERIC_RE.search(size) and not (_names_in(size) & set(tainted)):
            return "constant-length", f"explicit length {size.strip()} independent of tainted data"
        return ("", "")

    @staticmethod
    def _sink_category(
        callee: str, sink_categories: Dict[str, List[str]]
    ) -> Optional[str]:
        for category, names in sink_categories.items():
            if _match_patterns(callee, names) is not None:
                return category
        return None


def taint_chains_for(
    structure: Dict[str, Any], *, file: str = ""
) -> List[Dict[str, Any]]:
    """Convenience wrapper around :class:`TaintTracker`."""
    return TaintTracker().analyze(structure, file=file)


#: CWE ids this engine can express as a source-to-sink path. A finding in one
#: of these classes is expected to come with a chain; one outside them (a raw
#: integer overflow, say) is structural and the chain tracker has nothing to
#: say about it, so the absence of a chain is not evidence against it.
TAINT_MODELLED_CWES = frozenset(CWE_FOR_CATEGORY.values())

#: Sibling ids that name the same buffer-overflow write shape the engine
#: models under CWE-120. Juliet labels heap cases CWE-122 (and CWE-787 for
#: out-of-bounds writes) while Flawfinder reports the CWE-119 umbrella, so
#: without these aliases a CONFIRMED heap-overflow verdict would slip past
#: the chain-evidence gate that the design requires for modelled classes.
#: Buffer over-READS (CWE-125/126/127) are deliberately excluded: the engine
#: tracks data reaching a dangerous write sink, not data read out of bounds.
TAINT_MODELLED_ALIASES = frozenset({
    "CWE-118", "CWE-119", "CWE-121", "CWE-122", "CWE-123", "CWE-124",
    "CWE-131", "CWE-787", "CWE-788",
})


def taint_modelled(cwe: str) -> bool:
    """Whether ``cwe`` is a class this engine models as a data flow."""
    normalized = str(cwe or "").strip().upper()
    return normalized in TAINT_MODELLED_CWES or normalized in TAINT_MODELLED_ALIASES
