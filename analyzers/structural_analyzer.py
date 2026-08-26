from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

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
            name = self._text(source, name_node) if name_node else "<anonymous>"
            result.append(
                FunctionInfo(
                    name=name,
                    kind=node.type,
                    start_line=node.start_point.row + 1,
                    end_line=node.end_point.row + 1,
                    start_byte=node.start_byte,
                    end_byte=node.end_byte,
                    signature=self._text(source, node).split("\n", 1)[0].strip(),
                )
            )
        return result

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
        node_count = sum(1 for _ in self._walk(root))
        error_nodes = [n for n in self._walk(root) if n.type == "ERROR"]

        dangerous_calls = {
            "python": {
                "eval", "exec", "compile", "pickle.loads", "subprocess.call",
                "subprocess.run", "os.system", "os.popen",
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
