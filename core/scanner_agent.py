from typing import List, Dict, Any, Optional
from core.models import Vulnerability, Severity
from rules.python_rules import get_python_rules
from rules.c_rules import get_c_rules


class ScannerAgent:
    """
    Scanner Agent: Identifies potential vulnerability patterns in code.
    Uses rule-based pattern matching + LLM for context understanding.
    """

    def __init__(self, llm_client=None):
        self.llm_client = llm_client
        self.rules = {
            "python": get_python_rules(),
            "c": get_c_rules()
        }

    def scan(self, code: str, parsed_data: Dict[str, Any], language: str) -> List[Vulnerability]:
        """Scan code for potential vulnerabilities.

        Returns a list of vulnerability hypotheses with evidence.
        """
        vulnerabilities = []
        rules = self.rules.get(language.lower(), [])
        non_code_ranges = parsed_data.get("non_code_ranges", {})
        call_sites = parsed_data.get("call_sites", [])

        for rule in rules:
            matches = self._find_pattern_matches(code, rule, non_code_ranges, call_sites)
            for match in matches:
                vulnerabilities.append(Vulnerability(
                    cve=rule["cve"],
                    cwe=rule["cwe"],
                    name=rule["name"],
                    description=rule["description"],
                    location=f"{parsed_data.get('file', 'unknown')}:{match['line']}",
                    severity=Severity(rule["severity"]),
                    evidence=self._generate_evidence(code, rule, match),
                    confirmed=False,
                ))

        if self.llm_client and vulnerabilities:
            vulnerabilities = self._enrich_with_llm(vulnerabilities, code)

        return vulnerabilities

    def _find_pattern_matches(self, code: str, rule: Dict, non_code_ranges: Dict, call_sites: List[Dict]) -> List[Dict]:
        """Find pattern occurrences outside comments/strings/imports.

        Returns one entry per matched line:
        {"line": int, "pattern": str, "call_text": Optional[str]}.
        """
        matches = []
        lines = code.splitlines()
        ignore_if = rule.get("ignore_if", [])
        format_args = rule.get("format_args", {})

        for i, line in enumerate(lines, start=1):
            stripped_ranges = non_code_ranges.get(i, [])
            for pattern in rule["patterns"]:
                if not self._find_in_line(line, pattern, stripped_ranges):
                    continue
                if any(ig in line for ig in ignore_if):
                    continue
                if format_args and self._format_arg_is_literal(call_sites, i, format_args):
                    continue
                matches.append({
                    "line": i,
                    "pattern": pattern,
                    "call_text": self._matching_call_text(call_sites, i, pattern),
                })
                break
        return matches

    @staticmethod
    def _find_in_line(line: str, pattern: str, stripped_ranges: List[tuple]) -> bool:
        """True if `pattern` occurs on `line` outside the given non-code column ranges."""
        start = 0
        while True:
            idx = line.find(pattern, start)
            if idx == -1:
                return False
            overlap = any(
                idx < end_col and idx + len(pattern) > start_col
                for start_col, end_col in stripped_ranges
            )
            if not overlap:
                return True
            start = idx + 1

    @staticmethod
    def _format_arg_is_literal(call_sites: List[Dict], line: int, format_args: Dict) -> bool:
        """True if the format-string argument of a matching call is a literal string.

        `format_args` maps each sink name to the 0-based index of its format
        argument (e.g. {"printf": 0, "snprintf": 2}). If that argument is a
        string literal, the call is safe and should not be flagged.
        """
        for sink_name, arg_idx in format_args.items():
            for cs in call_sites:
                if cs["line"] != line or not cs["text"].startswith(sink_name):
                    continue
                args = cs.get("args", [])
                if arg_idx < len(args):
                    return args[arg_idx].lstrip().startswith(("\"", "'"))
        return False

    @staticmethod
    def _matching_call_text(call_sites: List[Dict], line: int, pattern: str) -> Optional[str]:
        for cs in call_sites:
            if cs["line"] == line and pattern in cs["text"]:
                return cs["text"]
        return None

    @staticmethod
    def _generate_evidence(code: str, rule: Dict, match: Dict) -> str:
        """Generate evidence description for a single vulnerability match."""
        line_num = match["line"]
        lines = code.splitlines()
        snippet = lines[line_num - 1].strip() if 0 < line_num <= len(lines) else ""

        evidence = f"Found pattern '{match['pattern']}' at line {line_num}"
        if snippet:
            evidence += f": {snippet}"
        if match.get("call_text"):
            evidence += f". Call: {match['call_text']}"
        evidence += f". This matches {rule['name']} ({rule['cve']})."

        # Per-sink sanitizer scope: only sanitizers on the same line count as mitigation.
        nearby = [s for s in rule.get("sanitizers", []) if s in lines[line_num - 1]]
        if nearby:
            evidence += f" Note: '{nearby[0]}' found on same line - may indicate mitigation."
        else:
            evidence += " No sanitizer found - potential vulnerability."

        return evidence

    def _enrich_with_llm(self, vulnerabilities: List[Vulnerability], code: str) -> List[Vulnerability]:
        """Use LLM to enrich vulnerability findings with context and remediation hints."""
        if not self.llm_client:
            return vulnerabilities

        try:
            code_excerpt = code[:2000] if len(code) > 2000 else code
            for vuln in vulnerabilities:
                prompt = (
                    "You are a senior application security engineer.\n"
                    f"Code under review (excerpt):\n```\n{code_excerpt}\n```\n\n"
                    f"Flagged issue: {vuln.name} ({vuln.cve}, {vuln.cwe})\n"
                    f"Location: {vuln.location}\n"
                    f"Current evidence: {vuln.evidence}\n\n"
                    "Reply in exactly this format with no extra text:\n"
                    "SEVERITY: <CRITICAL|HIGH|MEDIUM|LOW>\n"
                    "ANALYSIS: <one sentence confirming/refuting the finding>\n"
                    "FIX: <one sentence remediation>"
                )

                try:
                    if hasattr(self.llm_client, "invoke"):
                        response = self.llm_client.invoke(prompt)
                        content = response.content.strip()
                    else:
                        content = str(self.llm_client(prompt)).strip()

                    severity_line = next(
                        (l for l in content.splitlines() if l.upper().startswith("SEVERITY:")), ""
                    )
                    analysis_line = next(
                        (l for l in content.splitlines() if l.upper().startswith("ANALYSIS:")), ""
                    )
                    fix_line = next(
                        (l for l in content.splitlines() if l.upper().startswith("FIX:")), ""
                    )

                    sev_value = severity_line.split(":", 1)[1].strip().upper() if ":" in severity_line else ""
                    if sev_value in {s.value for s in Severity}:
                        vuln.severity = Severity(sev_value)

                    analysis_text = analysis_line.split(":", 1)[1].strip() if ":" in analysis_line else ""
                    fix_text = fix_line.split(":", 1)[1].strip() if ":" in fix_line else ""

                    placeholders = ["<one sentence>", "<one sentence confirming", "<one sentence remediation>", "<CRITICAL|HIGH|MEDIUM|LOW>"]
                    is_placeholder = any(tok in analysis_text or tok in fix_text for tok in placeholders)

                    if not is_placeholder and (analysis_text or fix_text):
                        llm_note = f"\nLLM: {analysis_text}"
                        if fix_text:
                            llm_note += f" | Fix: {fix_text}"
                        vuln.evidence += llm_note
                except Exception as inner:
                    print(f"LLM enrichment failed for {vuln.cve}: {inner}")

        except Exception as e:
            print(f"LLM enrichment failed: {e}")

        return vulnerabilities
