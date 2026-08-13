import re
from typing import List, Dict, Any, Optional
from core.models import Vulnerability

class VerifierAgent:
    """
    Verifier Agent: Validates vulnerability hypotheses by checking data flow.
    If an LLM client is provided, uses LLM for sophisticated data flow analysis;
    otherwise falls back to a heuristic.
    """

    # Source patterns indicating user-controlled input flowing into a sink.
    # Boundary guards prevent matching inside identifiers (e.g. copy_input()).
    _SOURCE_PATTERNS = [
        r"(?<![A-Za-z0-9_])request\.",
        r"getenv\s*\(",
        r"environ",
        r"sys\.argv",
        r"(?<![A-Za-z0-9_])argv",
        r"raw_input\s*\(",
        r"(?<![A-Za-z0-9_])input\s*\(",
        r"(?<![A-Za-z0-9_])stdin",
        r"form\.get",
        r"query_string",
        r"cookies",
    ]

    _SOURCE_REGEX = [re.compile(p) for p in _SOURCE_PATTERNS]

    def __init__(self, llm_client=None):
        self.llm_client = llm_client

    def verify(self, vulnerabilities: List[Vulnerability], code: str, parsed_data: Dict[str, Any]) -> List[Vulnerability]:
        """Verify each vulnerability hypothesis.

        Confirms only those with evidence that user input can reach the sink.
        """
        verified = []

        for vuln in vulnerabilities:
            confirmed = self._confirm(vuln, code, parsed_data)

            if confirmed:
                vuln.confirmed = True
                vuln.evidence += " Verified: Data flow confirmed."
            else:
                vuln.evidence += " Rejected: No clear data flow."

            verified.append(vuln)

        return verified

    def _confirm(self, vuln: Vulnerability, code: str, parsed_data: Dict[str, Any]) -> bool:
        """Tri-state confirmation: LLM verdict if unambiguous, otherwise heuristic."""
        if self.llm_client:
            llm_answer = self._analyze_data_flow_with_llm(vuln, code)
            if llm_answer is not None:
                return llm_answer
        return self._check_data_flow(vuln, code, parsed_data)

    def _check_data_flow(self, vuln: Vulnerability, code: str, parsed_data: Dict[str, Any]) -> bool:
        """Heuristic: confirm if a source can reach the sink.

        First-order: a source pattern appears inside the same enclosing function,
        on or above the vulnerable line.
        Second-order: the enclosing function is called somewhere with a tainted
        argument (parameter taint, e.g. copy_input(argv[1])).
        """
        lines = code.split("\n")
        try:
            vuln_line = int(vuln.location.split(":")[-1])
        except (ValueError, IndexError):
            return False

        body_start, body_end, func_name = self._enclosing_function(vuln_line, parsed_data.get("functions", []))

        if body_start is None:
            # No enclosing function (e.g. module-level code): use a small window.
            body_start = max(1, vuln_line - 8)
            body_end = min(len(lines), vuln_line + 2)

        # A source that appears below the sink cannot supply it,
        # so only inspect lines up to the vulnerable line.
        search_end = min(body_end, vuln_line)

        for line_no in range(body_start, search_end + 1):
            line = lines[line_no - 1]
            if self._is_source(line):
                return True

        if func_name and self._called_with_tainted_arg(func_name, parsed_data.get("call_sites", [])):
            return True

        return False

    @staticmethod
    def _is_source(line: str) -> bool:
        return any(regex.search(line) for regex in VerifierAgent._SOURCE_REGEX)

    @staticmethod
    def _called_with_tainted_arg(func_name: str, call_sites: List[Dict]) -> bool:
        """True if a call site passes a tainted argument to func_name."""
        for cs in call_sites:
            text = cs.get("text", "")
            args = cs.get("args") or []
            if text.startswith(func_name + "(") and args:
                if VerifierAgent._is_source(" ".join(args)):
                    return True
        return False

    @staticmethod
    def _enclosing_function(vuln_line: int, functions: List[Dict]) -> tuple:
        """Return (start_line, end_line, name) of the function containing
        vuln_line, or (None, None, None)."""
        for fn in functions:
            start = fn.get("start_line")
            end = fn.get("end_line")
            if start is not None and end is not None and start <= vuln_line <= end:
                return start, end, fn.get("name")
        return None, None, None

    def _analyze_data_flow_with_llm(self, vuln: Vulnerability, code: str) -> Optional[bool]:
        """
        Ask the LLM whether user input can reach the vulnerable sink.

        Returns True/False on an unambiguous YES/NO, otherwise None (ambiguous),
        so the caller can fall back to the heuristic.
        """
        if not self.llm_client:
            return None

        try:
            context = self._get_code_context(code, vuln.location, lines=30)
            prompt = (
                "You are a security expert. Analyze the following code snippet and "
                "determine if user-controlled input can reach the vulnerable function.\n\n"
                f"Vulnerability: {vuln.name} ({vuln.cve})\n"
                f"CWE: {vuln.cwe}\n"
                f"Description: {vuln.description}\n"
                f"Location: {vuln.location}\n\n"
                f"Code context:\n{context}\n\n"
                'Answer with only "YES" if user input reaches the vulnerable function, '
                'otherwise "NO". Provide no additional text.'
            )

            if hasattr(self.llm_client, "invoke"):
                response = self.llm_client.invoke(prompt)
                answer = response.content.strip()
            else:
                answer = str(self.llm_client(prompt)).strip()

            upper = answer.upper()
            if upper in {"YES", "NO", "YES.", "NO."}:
                return upper.startswith("YES")
            # Refuse placeholder/verbose answers; let the heuristic decide.
            if "YES" in upper and "NO" not in upper:
                return True
            if "NO" in upper and "YES" not in upper:
                return False
            return None

        except Exception as e:
            print(f"LLM analysis failed for {vuln.cve}: {e}")
            return None

    def _get_code_context(self, code: str, location: str, lines: int = 20) -> str:
        """Extract context lines around the vulnerability location."""
        try:
            line_num = int(location.split(":")[-1])
            code_lines = code.split("\n")
            start = max(0, line_num - lines // 2)
            end = min(len(code_lines), line_num + lines // 2)
            context_lines = []
            for i in range(start, end):
                context_lines.append(f"{i + 1}: {code_lines[i]}")
            return "\n".join(context_lines)
        except (ValueError, IndexError):
            return code[:1000]