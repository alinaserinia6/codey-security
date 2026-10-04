from __future__ import annotations

from dataclasses import dataclass, asdict
from dataclasses import field as dataclasses_field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from tree_sitter import Language, Parser

try:
    import tree_sitter_python as ts_python
except ImportError:
    ts_python = None

try:
    import tree_sitter_c as ts_c
except ImportError:
    ts_c = None

try:
    import tree_sitter_cpp as ts_cpp
except ImportError:
    ts_cpp = None


PYTHON_EXTENSIONS = {".py", ".pyw"}
C_EXTENSIONS = {".c", ".h"}
CPP_EXTENSIONS = {".cc", ".cp", ".cpp", ".cxx", ".hh", ".hpp", ".hxx"}


@dataclass
class FunctionInfo:
    name: str
    kind: str
    start_line: int
    end_line: int
    start_byte: int
    end_byte: int
    signature: str
    parameters: List[str] = dataclasses_field(default_factory=list)


@dataclass
class CallInfo:
    name: str
    line: int
    column: int
    expression: str


@dataclass
class ImportInfo:
    name: str
    line: int
    kind: str


@dataclass
class AssignmentInfo:
    """A binding: which names are written, and the expression that is read.

    Assignments are what turn a source call into a named value that can later
    reach a sink, so the taint tracker works on these rather than guessing at
    bindings from call expressions.
    """

    targets: List[str]
    value: str
    line: int
    kind: str


@dataclass
class ReferenceInfo:
    """A bare identifier, attribute access or subscript read in the source."""

    text: str
    line: int
    column: int
    kind: str


@dataclass
class GlobalInfo:
    """A file-scope variable declaration.

    Juliet test cases hand attacker data between source files through globals
    (``extern int * ..._badData``), so the file-scope names are needed for
    taint to cross function boundaries the same way a parameter would.
    """

    names: List[str]
    line: int
    storage: str = "file-scope"


class StructuralAnalyzer:
    """Language-aware structural indexing using official Tree-sitter bindings."""

    def __init__(self) -> None:
        self._parsers: Dict[str, Parser] = {}

    @staticmethod
    def detect_language(path: Path) -> str:
        ext = path.suffix.lower()
        if ext in PYTHON_EXTENSIONS:
            return "python"
        if ext in C_EXTENSIONS:
            return "c"
        if ext in CPP_EXTENSIONS:
            return "cpp"
        raise ValueError(f"Unsupported source extension: {ext}")

    def _language(self, language: str) -> Language:
        if language == "python":
            if ts_python is None:
                raise RuntimeError("tree-sitter-python is not installed")
            return Language(ts_python.language())
        if language == "c":
            if ts_c is None:
                raise RuntimeError("tree-sitter-c is not installed")
            return Language(ts_c.language())
        if language == "cpp":
            if ts_cpp is None:
                raise RuntimeError("tree-sitter-cpp is not installed")
            return Language(ts_cpp.language())
        raise ValueError(f"Unsupported language: {language}")

    def _parser(self, language: str) -> Parser:
        if language not in self._parsers:
            self._parsers[language] = Parser(self._language(language))
        return self._parsers[language]

    @staticmethod
    def _text(source: bytes, node: Any) -> str:
        return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")

    @staticmethod
    def _walk(root: Any) -> Iterable[Any]:
        stack = [root]
        while stack:
            node = stack.pop()
            yield node
            stack.extend(reversed(node.children))

    @staticmethod
    def _first_descendant(node: Any, types: set[str]) -> Optional[Any]:
        for child in StructuralAnalyzer._walk(node):
            if child.type in types:
                return child
        return None

    def _extract_functions(self, root: Any, source: bytes, language: str) -> List[FunctionInfo]:
        result: List[FunctionInfo] = []
        if language == "python":
            function_types = {"function_definition", "async_function_definition"}
        else:
            function_types = {"function_definition"}

        for node in self._walk(root):
            if node.type not in function_types:
                continue
            name_node = node.child_by_field_name("name")
            if name_node is not None:
                name = self._text(source, name_node)
            elif language != "python":
                name = self._find_declarator_name(node, source) or "<anonymous>"
            else:
                name = "<anonymous>"
            parameters_node = node.child_by_field_name("parameters")
            if parameters_node is None:
                # C nests the list under the declarator:
                # function_definition -> function_declarator -> parameter_list.
                parameters_node = self._find_parameter_list(node, source)
            parameters = (
                self._parameter_names(parameters_node, source)
                if parameters_node is not None
                else []
            )
            result.append(
                FunctionInfo(
                    name=name,
                    kind=node.type,
                    start_line=node.start_point.row + 1,
                    end_line=node.end_point.row + 1,
                    start_byte=node.start_byte,
                    end_byte=node.end_byte,
                    signature=self._text(source, node).split("\n", 1)[0].strip(),
                    parameters=parameters,
                )
            )
        return result

    @staticmethod
    def _find_parameter_list(node: Any, source: bytes) -> Optional[Any]:
        """Locate the parameter list of a C/C++ function definition.

        Python exposes it as a ``parameters`` field, but C hangs the list off
        the declarator (``function_declarator`` -> ``parameter_list``), which is
        why the field lookup alone comes back empty for C.
        """
        for child in node.children:
            if child.type == "parameter_list":
                return child
            if child.type in {
                "function_declarator", "declarator", "pointer_declarator",
                "parenthesized_declarator", "reference_declarator",
            }:
                found = StructuralAnalyzer._find_parameter_list(child, source)
                if found is not None:
                    return found
        return None

    @staticmethod
    def _find_declarator_name(node: Any, source: bytes) -> Optional[str]:
        """The declared name of a C/C++ function definition.

        Python exposes the name as a ``name`` field, but C and C++ hang it off
        the declarator chain (``function_definition`` -> ``function_declarator``
        -> ``field_identifier``), which is why the field lookup comes back
        empty and every C function would otherwise be reported as anonymous.
        The parameter list is skipped so a parameter's identifier is never
        mistaken for the function's own name.
        """
        name_types = {
            "field_identifier", "identifier", "qualified_identifier",
            "destructor_name", "operator_name", "type_identifier",
        }
        stack: List[Any] = list(node.children)
        while stack:
            child = stack.pop(0)
            if child.type == "parameter_list":
                continue
            if child.type in name_types:
                return StructuralAnalyzer._text(source, child)
            stack.extend(child.children)
        return None

    def _parameter_names(self, node: Any, source: bytes) -> List[str]:
        """Parameter names of a function, for either language.

        Python wraps them in a ``parameters`` node, C in ``parameter_list``; in
        both cases only the declared names are collected, not the types.
        """
        names: List[str] = []
        for child in node.children:
            if child.type in {
                "identifier", "typed_parameter", "optional_parameter",
                "default_parameter", "list_splat_pattern", "dictionary_splat_pattern",
                "parameter_declaration",
            }:
                name = self._declared_name(child, source)
                if name:
                    names.append(name)
            elif child.type in {
                "parameters", "parameter_list", "identifier_list", "variadic_parameter",
            }:
                names.extend(self._parameter_names(child, source))
            elif child.type == "variadic_parameter_declaration":
                for grandchild in child.children:
                    if grandchild.type == "identifier":
                        names.append(self._text(source, grandchild))
                        break
        return names

    def _declared_name(self, node: Any, source: bytes) -> str:
        """The bound name of a parameter node."""
        for child in node.children:
            if child.type == "identifier":
                return self._text(source, child)
        if node.type == "identifier":
            return self._text(source, node)
        # A pointer/array parameter (``char *buf``) nests its declarator, and a
        # C++ reference or const-reference parameter
        # (``const std::string& in``) nests one inside a ``type_qualifier``.
        # Descending is what keeps a reference parameter from being reported as
        # unnamed, which would hide it as a taint source.
        declarator_types = {
            "pointer_declarator", "array_declarator", "identifier",
            "reference_declarator", "type_qualifier", "init_declarator",
        }
        # Each candidate is tried in turn rather than returning on the first
        # one: in ``const std::string& in`` the ``type_qualifier`` comes before
        # the ``reference_declarator`` that actually carries the name.
        for child in node.children:
            if child.type in declarator_types:
                name = self._declared_name(child, source)
                if name:
                    return name
        return ""

    def _extract_calls(self, root: Any, source: bytes, language: str) -> List[CallInfo]:
        call_types = {"call", "call_expression"}
        result: List[CallInfo] = []
        for node in self._walk(root):
            if node.type not in call_types:
                continue
            function_node = node.child_by_field_name("function")
            if function_node is None:
                # Python's call node may expose the callable as the first child.
                function_node = node.children[0] if node.children else None
            if function_node is None:
                continue
            expression = self._text(source, function_node).strip()
            if not expression:
                continue
            result.append(
                CallInfo(
                    name=expression,
                    line=node.start_point.row + 1,
                    column=node.start_point.column + 1,
                    expression=self._text(source, node).strip(),
                )
            )
        return result

    def _extract_imports(self, root: Any, source: bytes, language: str) -> List[ImportInfo]:
        if language == "python":
            import_types = {"import_statement", "import_from_statement"}
        else:
            import_types = {"preproc_include"}

        result: List[ImportInfo] = []
        for node in self._walk(root):
            if node.type not in import_types:
                continue
            result.append(
                ImportInfo(
                    name=self._text(source, node).strip(),
                    line=node.start_point.row + 1,
                    kind=node.type,
                )
            )
        return result

    def _extract_assignments(
        self, root: Any, source: bytes, language: str
    ) -> List[AssignmentInfo]:
        """Collect every binding in the file.

        Python exposes ``assignment``/``augmented_assignment`` with ``left`` and
        ``right`` fields; C wraps initialisers in ``init_declarator`` and bare
        writes in ``assignment_expression``.
        """
        result: List[AssignmentInfo] = []
        for node in self._walk(root):
            if node.type in {"assignment", "augmented_assignment"}:
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                if left is None or right is None:
                    continue
                result.append(
                    AssignmentInfo(
                        targets=[t for t in self._target_names(left, source) if t],
                        value=self._text(source, right).strip(),
                        line=node.start_point.row + 1,
                        kind=node.type,
                    )
                )
            elif node.type == "assignment_expression":
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                if left is None or right is None:
                    continue
                result.append(
                    AssignmentInfo(
                        targets=[t for t in self._target_names(left, source) if t],
                        value=self._text(source, right).strip(),
                        line=node.start_point.row + 1,
                        kind="assignment_expression",
                    )
                )
            elif node.type == "init_declarator":
                declarator = node.child_by_field_name("declarator")
                value = node.child_by_field_name("value")
                if declarator is None or value is None:
                    continue
                result.append(
                    AssignmentInfo(
                        targets=[t for t in self._target_names(declarator, source) if t],
                        value=self._text(source, value).strip(),
                        line=node.start_point.row + 1,
                        kind="declaration",
                    )
                )
            elif node.type == "declaration" and not self._has_initializer(node):
                # A declaration with no initialiser (``char buf[10]``) still
                # declares a buffer worth knowing about, so it is indexed with
                # an empty value: taint ignores it, the report does not.
                targets: List[str] = []
                declarators = [
                    child
                    for child in node.children
                    if child.type
                    in {
                        "array_declarator", "pointer_declarator", "identifier",
                        "function_declarator",
                    }
                ]
                for declarator in declarators or [node]:
                    for name in self._target_names(declarator, source):
                        if name not in targets:
                            targets.append(name)
                if targets:
                    result.append(
                        AssignmentInfo(
                            targets=targets,
                            value="",
                            line=node.start_point.row + 1,
                            kind="declaration",
                        )
                    )
        return result

    @staticmethod
    def _has_initializer(node: Any) -> bool:
        return any(
            child.type == "init_declarator" for child in node.children
        )

    def _target_names(self, node: Any, source: bytes) -> List[str]:
        """Identifiers written by a binding target.

        Subscript writes (``data["k"] = v``) and array/pointer declarators
        (``char buf[10]``) bind through a base identifier, so the base name is
        what taint is attached to.
        """
        if node.type in {"identifier", "field_identifier", "type_identifier"}:
            return [self._text(source, node)]
        if node.type in {"subscript", "array_subscript"}:
            for child in node.children:
                if child.type in {"identifier", "attribute"}:
                    return [self._text(source, child)]
            return []
        if node.type in {"array_declarator", "pointer_declarator", "init_declarator"}:
            for child in node.children:
                if child.type in {"identifier", "pointer_declarator", "array_declarator"}:
                    return self._target_names(child, source)
            return []
        if node.type == "attribute":
            for child in node.children:
                if child.type in {"identifier", "attribute"}:
                    return [self._text(source, child)]
        return []

    def _extract_globals(self, root: Any, source: bytes) -> List[GlobalInfo]:
        """File-scope variable declarations, excluding function definitions."""
        result: List[GlobalInfo] = []
        for child in root.children:
            if child.type not in {"declaration", "type_definition", "linkage_specification"}:
                continue
            names: List[str] = []
            for node in self._walk(child):
                if node.type not in {
                    "identifier", "init_declarator", "array_declarator",
                    "pointer_declarator",
                }:
                    continue
                for name in self._target_names(node, source):
                    if name not in names:
                        names.append(name)
            if names:
                result.append(
                    GlobalInfo(
                        names=names,
                        line=child.start_point.row + 1,
                        storage="file-scope",
                    )
                )
        return result

    def _extract_references(
        self, root: Any, source: bytes, language: str
    ) -> List[ReferenceInfo]:
        """Identifiers, attribute reads and subscripts, as dataflow entry points.

        ``sys.argv[1]`` and ``request.args`` are not calls, so a taint engine
        driven only by the call index would miss them entirely.
        """
        result: List[ReferenceInfo] = []
        for node in self._walk(root):
            if node.type not in {"identifier", "attribute", "subscript", "array_subscript"}:
                continue
            text = self._text(source, node).strip()
            if not text or len(text) > 200:
                continue
            result.append(
                ReferenceInfo(
                    text=text,
                    line=node.start_point.row + 1,
                    column=node.start_point.column + 1,
                    kind=node.type,
                )
            )
        return result

    def analyze_file(self, path: str | Path) -> Dict[str, Any]:
        source_path = Path(path).resolve()
        source = source_path.read_bytes()
        language = self.detect_language(source_path)
        parser = self._parser(language)
        tree = parser.parse(source)
        root = tree.root_node

        functions = self._extract_functions(root, source, language)
        calls = self._extract_calls(root, source, language)
        imports = self._extract_imports(root, source, language)
        assignments = self._extract_assignments(root, source, language)
        references = self._extract_references(root, source, language)
        globals_found = self._extract_globals(root, source)
        node_count = sum(1 for _ in self._walk(root))
        error_nodes = [n for n in self._walk(root) if n.type == "ERROR"]

        dangerous_calls = {
            "python": {
                "eval", "exec", "compile", "pickle.loads", "subprocess.call",
                "subprocess.run", "os.system", "os.popen", "yaml.load",
                "render_template_string", "input", "os.getenv",
            },
            "c": {
                "strcpy", "strcat", "sprintf", "gets", "scanf", "sscanf",
                "memcpy", "memmove", "system", "popen", "printf",
            },
            "cpp": {
                "strcpy", "strcat", "sprintf", "gets", "scanf", "sscanf",
                "memcpy", "memmove", "system", "popen", "printf",
            },
        }[language]

        dangerous = [call for call in calls if call.name in dangerous_calls or call.name.split("::")[-1] in dangerous_calls]

        branch_types = {
            "python": {"if_statement", "for_statement", "while_statement", "try_statement", "match_statement"},
            "c": {"if_statement", "for_statement", "while_statement", "switch_statement", "do_statement"},
            "cpp": {"if_statement", "for_statement", "while_statement", "switch_statement", "do_statement", "try_statement"},
        }[language]
        branch_count = sum(1 for node in self._walk(root) if node.type in branch_types)

        return {
            "path": str(source_path),
            "language": language,
            "parser": "tree-sitter",
            "parse_has_errors": bool(error_nodes),
            "parse_error_count": len(error_nodes),
            "node_count": node_count,
            "branch_count": branch_count,
            "functions": [asdict(item) for item in functions],
            "calls": [asdict(item) for item in calls],
            "imports": [asdict(item) for item in imports],
            "assignments": [asdict(item) for item in assignments],
            "references": [asdict(item) for item in references],
            "globals": [asdict(item) for item in globals_found],
            "dangerous_calls": [asdict(item) for item in dangerous],
        }

    def analyze_path(self, path: str | Path, recursive: bool = True) -> List[Dict[str, Any]]:
        source_path = Path(path)
        if source_path.is_file():
            return [self.analyze_file(source_path)]

        results: List[Dict[str, Any]] = []
        iterator = source_path.rglob("*") if recursive else source_path.glob("*")
        for candidate in iterator:
            if not candidate.is_file():
                continue
            if candidate.suffix.lower() in PYTHON_EXTENSIONS | C_EXTENSIONS | CPP_EXTENSIONS:
                try:
                    results.append(self.analyze_file(candidate))
                except (OSError, UnicodeError, ValueError, RuntimeError) as exc:
                    results.append(
                        {
                            "path": str(candidate.resolve()),
                            "language": "unknown",
                            "parser": "tree-sitter",
                            "error": str(exc),
                        }
                    )
        return results
