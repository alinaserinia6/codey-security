from typing import List, Dict, Any
from core.models import Vulnerability, Severity
from rules.python_rules import get_python_rules
from rules.c_rules import get_c_rules
import re

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
        """Use LLM to enrich vulnerability findings with context."""
        if not self.llm_client:
            return vulnerabilities
        
        try:
            # Prepare context for LLM
            context = f"Analyze this code for vulnerabilities:\n\n```\n{code[:2000]}\n```\n\n"
            context += "Current findings:\n"
            for v in vulnerabilities:
                context += f"- {v.cve}: {v.name} at {v.location}\n"
            
            context += "\nProvide a brief analysis of each finding."
            
            # Call LLM (simplified - in production use proper LangChain)
            # response = self.llm_client.invoke(context)
            # ... enrich vulnerabilities with LLM response
            
        except Exception as e:
            print(f"LLM enrichment failed: {e}")
        
        return vulnerabilities
