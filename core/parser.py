import tree_sitter_python as tspython
import tree_sitter_c as tsc
from tree_sitter import Language, Parser, Query, QueryCursor
from typing import List, Dict, Any, Tuple

class CodeParser:
    """Parses source code using Tree-sitter and extracts functions, calls, and non-code line ranges."""

    # Node types that should never count as a code match for a vulnerability pattern.
    _NON_CODE_TYPES = {
        "comment",
        "string",
        "string_literal",
        "import_statement",
        "import_from_statement",
        "preproc_include",
    }

    def __init__(self):
        self.parsers = {}
        self._init_parsers()

    def _init_parsers(self):
        """Initialize Tree-sitter parsers for supported languages."""
        try:
            # Python parser
            py_lang = Language(tspython.language())
            py_parser = Parser(py_lang)
            self.parsers["python"] = py_parser

            # C parser
            c_lang = Language(tsc.language())
            c_parser = Parser(c_lang)
            self.parsers["c"] = c_parser
        except Exception as e:
            print(f"Warning: Could not initialize Tree-sitter: {e}")

    def parse(self, code: str, language: str) -> Dict[str, Any]:
        """Parse source code and extract relevant information."""
        if language not in self.parsers:
            return {"error": f"Language {language} not supported"}

        parser = self.parsers[language]
        tree = parser.parse(bytes(code, "utf-8"))
        root = tree.root_node

        print(root)
        exit(0)

        result = {
            "functions": self._extract_functions(root, language),
            "call_sites": self._extract_call_sites(root, language),
            "imports": self._extract_imports(root, language),
            "non_code_ranges": self._extract_non_code_ranges(code, root),
        }

        return result

    @staticmethod
    def _walk(node):
        """Yield `node` and all of its descendants."""
        yield node
        for child in node.children:
            yield from CodeParser._walk(child)

    def _extract_functions(self, node, language: str) -> List[Dict]:
        """Extract function definitions with their full line span."""
        functions = []
        query_str = self._get_function_query(language)

        if not query_str:
            return functions

        try:
            query = Query(self.parsers[language].language, query_str)
            cursor = QueryCursor(query)
            captures = cursor.captures(node)

            for name, nodes in captures.items():
                if name == "function":
                    for func_node in nodes:
                        func_name = self._function_name(func_node, language)
                        if not func_name:
                            continue
                        functions.append({
                            "name": func_name,
                            "start_line": func_node.start_point[0] + 1,
                            "end_line": func_node.end_point[0] + 1
                        })
        except Exception as e:
            print(f"Error extracting functions: {e}")

        return functions

    @staticmethod
    def _function_name(func_node, language: str):
        """Extract the function name from a function_definition node."""
        name_field = func_node.child_by_field_name("name")
        if name_field is not None:
            return name_field.text.decode("utf-8")
        # C: name lives under declarator -> declarator
        declarator = func_node.child_by_field_name("declarator")
        if declarator is not None:
            name_field = declarator.child_by_field_name("declarator")
            if name_field is not None:
                return name_field.text.decode("utf-8")
        return None

    def _extract_call_sites(self, node, language: str) -> List[Dict]:
        """Extract function call sites with their text and start line.

        A direct AST walker is used instead of a tree-sitter `(call)` query because
        query captures can yield duplicate/unreliable matches.
        """
        call_sites = []
        target_type = "call" if language == "python" else "call_expression"
        seen = set()

        for call_node in self._walk(node):
            if call_node.type != target_type:
                continue
            key = (call_node.start_byte, call_node.end_byte)
            if key in seen:
                continue
            seen.add(key)
            call_sites.append({
                "text": call_node.text.decode("utf-8"),
                "line": call_node.start_point[0] + 1,
                "start_col": call_node.start_point[1],
                "end_col": call_node.end_point[1],
                "args": self._call_args(call_node),
            })

        return call_sites

    @staticmethod
    def _call_args(call_node) -> List[str]:
        """Extract the source text of each argument of a call node."""
        arg_list = next(
            (c for c in call_node.children if c.type == "argument_list"),
            None,
        )
        if arg_list is None:
            return []
        return [
            c.text.decode("utf-8")
            for c in arg_list.children
            if c.type not in ("(", ")", ",")
        ]

    def _extract_non_code_ranges(self, code: str, node) -> Dict[int, List[Tuple[int, int]]]:
        """Return 1-indexed line number -> list of 0-indexed column ranges that are
        comments, string literals, or import/include statements.

        Column ranges (rather than whole lines) are used so that a vulnerability
        pattern on a line like `x = subprocess.call(cmd)  # eval` is still detected
        even though trailing comments are stripped.
        """
        lines = code.splitlines()
        ranges: Dict[int, List[Tuple[int, int]]] = {}

        def add(line, start_col, end_col):
            if end_col <= start_col:
                return
            ranges.setdefault(line, []).append((start_col, end_col))

        for child in self._walk(node):
            if child.type not in self._NON_CODE_TYPES:
                continue
            start_line = child.start_point[0] + 1
            end_line = child.end_point[0] + 1
            start_col = child.start_point[1]
            end_col = child.end_point[1]

            if start_line == end_line:
                add(start_line, start_col, end_col)
            else:
                add(start_line, start_col, len(lines[start_line - 1]))
                for ln in range(start_line + 1, end_line):
                    add(ln, 0, len(lines[ln - 1]))
                add(end_line, 0, end_col)

        return ranges

    def _extract_imports(self, node, language: str) -> List[str]:
        """Extract import statements."""
        imports = []
        query_str = self._get_import_query(language)

        if not query_str:
            return imports

        try:
            query = Query(self.parsers[language].language, query_str)
            cursor = QueryCursor(query)
            captures = cursor.captures(node)

            for name, nodes in captures.items():
                if name == "import":
                    for node in nodes:
                        imports.append(node.text.decode("utf-8"))
        except Exception:
            pass

        return imports

    def _get_function_query(self, language: str) -> str:
        queries = {
            "python": """
                (function_definition) @function
                (class_definition
                    body: (block
                        (function_definition) @function))
            """,
            "c": """
                (function_definition) @function
            """
        }
        return queries.get(language, "")

    def _get_import_query(self, language: str) -> str:
        queries = {
            "python": """
                (import_statement name: (dotted_name) @import)
                (import_from_statement module_name: (dotted_name) @import)
            """,
            "c": "(preproc_include path: (string_literal) @import)"
        }
        return queries.get(language, "")