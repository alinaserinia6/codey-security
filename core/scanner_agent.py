from typing import List, Dict, Any
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
        """
        Scan code for potential vulnerabilities.
        Returns a list of vulnerability hypotheses with evidence.
        """
        vulnerabilities = []
        rules = self.rules.get(language.lower(), [])
        
        for rule in rules:
            matches = self._find_pattern_matches(code, rule["patterns"])
            if matches:
                # Create vulnerability hypothesis
                vuln = Vulnerability(
                    cve=rule["cve"],
                    cwe=rule["cwe"],
                    name=rule["name"],
                    description=rule["description"],
                    location=f"{parsed_data.get('file', 'unknown')}:{matches[0]}",
                    severity=Severity(rule["severity"]),
                    evidence=self._generate_evidence(code, rule, matches),
                    confirmed=False
                )
                vulnerabilities.append(vuln)
        
        # Use LLM to enrich findings (if available)
        if self.llm_client and vulnerabilities:
            vulnerabilities = self._enrich_with_llm(vulnerabilities, code)
        
        return vulnerabilities
    
    def _find_pattern_matches(self, code: str, patterns: List[str]) -> List[int]:
        """Find line numbers where patterns occur."""
        matches = []
        lines = code.split("\n")
        for i, line in enumerate(lines):
            for pattern in patterns:
                if pattern in line:
                    matches.append(i + 1)
                    break
        return matches
    
    def _generate_evidence(self, code: str, rule: Dict, matches: List[int]) -> str:
        """Generate evidence description for a vulnerability."""
        evidence = f"Found pattern '{rule['patterns'][0]}' at lines {matches[:3]}"
        evidence += f". This matches {rule['name']} ({rule['cve']})."
        
        # Check if sanitizer is present
        sanitizer_found = False
        for sanitizer in rule.get("sanitizers", []):
            if sanitizer in code:
                sanitizer_found = True
                evidence += f" Note: '{sanitizer}' found nearby - may indicate mitigation."
                break
        
        if not sanitizer_found:
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

                    sev_value = severity_line.split(":", 1)[1].strip().upper()
                    if sev_value in {s.value for s in Severity}:
                        vuln.severity = Severity(sev_value)

                    analysis_text = analysis_line.split(":", 1)[1].strip() if analysis_line else ""
                    fix_text = fix_line.split(":", 1)[1].strip() if fix_line else ""
                    if analysis_text or fix_text:
                        llm_note = f"\n🤖 LLM: {analysis_text}"
                        if fix_text:
                            llm_note += f" | Fix: {fix_text}"
                        vuln.evidence += llm_note
                except Exception as inner:
                    print(f"LLM enrichment failed for {vuln.cve}: {inner}")

        except Exception as e:
            print(f"LLM enrichment failed: {e}")

        return vulnerabilities
