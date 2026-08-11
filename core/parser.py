import tree_sitter_python as tspython
import tree_sitter_c as tsc
from tree_sitter import Language, Parser, Query, QueryCursor
from typing import List, Dict, Any

class CodeParser:
    """Parses source code using Tree-sitter and extracts functions, calls, and sensitive patterns."""
    
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
        
        result = {
            "functions": self._extract_functions(root, language),
            "calls": self._extract_calls(root, language),
            "sensitive_calls": [],
            "imports": self._extract_imports(root, language)
        }
        
        # Extract sensitive function calls based on language
        if language == "python":
            result["sensitive_calls"] = self._extract_python_sensitive_calls(root)
        elif language == "c":
            result["sensitive_calls"] = self._extract_c_sensitive_calls(root)
        
        return result
    
    def _extract_functions(self, node, language: str) -> List[Dict]:
        """Extract function definitions."""
        functions = []
        query_str = self._get_function_query(language)
        
        if not query_str:
            return functions
        
        try:
            lang = self.parsers[language].language
            query = Query(lang, query_str)
            cursor = QueryCursor(query)
            captures = cursor.captures(node)

            for name, nodes in captures.items():
                if name == "function.name":
                    for func_node in nodes:
                        functions.append({
                            "name": func_node.text.decode("utf-8"),
                            "start_line": func_node.start_point[0] + 1,
                            "end_line": func_node.end_point[0] + 1
                        })
        except Exception as e:
            print(f"Error extracting functions: {e}")

        return functions
    
    def _extract_calls(self, node, language: str) -> List[str]:
        """Extract function calls."""
        calls = []
        query_str = self._get_call_query(language)
        
        if not query_str:
            return calls
        
        try:
            lang = self.parsers[language].language
            query = Query(lang, query_str)
            cursor = QueryCursor(query)
            captures = cursor.captures(node)

            for name, nodes in captures.items():
                if name == "call":
                    for node in nodes:
                        calls.append(node.text.decode("utf-8"))
        except Exception:
            pass
        
        return calls
    
    def _extract_imports(self, node, language: str) -> List[str]:
        """Extract import statements."""
        imports = []
        query_str = self._get_import_query(language)
        
        if not query_str:
            return imports
        
        try:
            lang = self.parsers[language].language
            query = Query(lang, query_str)
            cursor = QueryCursor(query)
            captures = cursor.captures(node)

            for name, nodes in captures.items():
                if name == "import":
                    for node in nodes:
                        imports.append(node.text.decode("utf-8"))
        except Exception:
            pass

        return imports
    
    def _extract_python_sensitive_calls(self, node) -> List[Dict]:
        """Extract sensitive Python function calls (eval, exec, etc.)."""
        sensitive = []
        patterns = [
            ("eval", "CWE-95", "Dynamic code evaluation"),
            ("exec", "CWE-95", "Dynamic code execution"),
            ("render_template_string", "CWE-94", "Template injection"),
            ("yaml.load", "CWE-502", "Unsafe deserialization"),
            ("yaml.unsafe_load", "CWE-502", "Unsafe deserialization"),
            ("pickle.loads", "CWE-502", "Unsafe deserialization"),
        ]
        
        # Simple text-based search for sensitive calls (in production, use AST traversal)
        code = node.text.decode("utf-8") if hasattr(node, "text") else ""
        for pattern, cwe, desc in patterns:
            if pattern in code:
                sensitive.append({
                    "pattern": pattern,
                    "cwe": cwe,
                    "description": desc,
                    "line": self._find_line(code, pattern)
                })
        
        return sensitive
    
    def _extract_c_sensitive_calls(self, node) -> List[Dict]:
        """Extract sensitive C function calls."""
        sensitive = []
        patterns = [
            ("strcpy", "CWE-119", "Buffer overflow risk"),
            ("strcat", "CWE-119", "Buffer overflow risk"),
            ("sprintf", "CWE-119", "Buffer overflow risk"),
            ("gets", "CWE-119", "Buffer overflow risk"),
            ("scanf", "CWE-119", "Buffer overflow risk"),
            ("system", "CWE-78", "Command injection"),
        ]
        
        code = node.text.decode("utf-8") if hasattr(node, "text") else ""
        for pattern, cwe, desc in patterns:
            if pattern in code:
                sensitive.append({
                    "pattern": pattern,
                    "cwe": cwe,
                    "description": desc,
                    "line": self._find_line(code, pattern)
                })
        
        return sensitive
    
    def _find_line(self, code: str, pattern: str) -> int:
        """Find line number of a pattern in code."""
        lines = code.split("\n")
        for i, line in enumerate(lines):
            if pattern in line:
                return i + 1
        return 0
    
    def _get_function_query(self, language: str) -> str:
        queries = {
            "python": """
                (function_definition
                    name: (identifier) @function.name)
                (class_definition
                    body: (block
                        (function_definition
                            name: (identifier) @function.name)))
            """,
            "c": """
                (function_definition
                    declarator: (function_declarator
                        declarator: (identifier) @function.name))
            """
        }
        return queries.get(language, "")
    
    def _get_call_query(self, language: str) -> str:
        queries = {
            "python": "(call function: (identifier) @call)",
            "c": "(call_expression function: (identifier) @call)"
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
