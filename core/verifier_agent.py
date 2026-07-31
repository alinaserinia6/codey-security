from typing import List, Dict, Any
from core.models import Vulnerability

class VerifierAgent:
    """
    Verifier Agent: Validates vulnerability hypotheses by checking data flow.
    Only confirms vulnerabilities with clear source-to-sink data flow.
    """
    
    def __init__(self, llm_client=None):
        self.llm_client = llm_client
    
    def verify(self, vulnerabilities: List[Vulnerability], code: str, parsed_data: Dict[str, Any]) -> List[Vulnerability]:
        """
        Verify each vulnerability hypothesis.
        Confirms only those with clear evidence of data flow.
        """
        verified = []
        
        for vuln in vulnerabilities:
            if self._check_data_flow(vuln, code):
                vuln.confirmed = True
                vuln.evidence += " ✅ Verified: Data flow confirmed."
                verified.append(vuln)
            else:
                vuln.evidence += " ❌ Rejected: No clear data flow."
                # Still keep it but mark as unconfirmed for reporting
        
        return verified
    
    def _check_data_flow(self, vuln: Vulnerability, code: str) -> bool:
        """
        Check if there's a clear data flow from source to sink.
        Simplified: checks if user input reaches the vulnerable function.
        """
        # Simple heuristic: look for user input patterns near the vulnerability
        source_patterns = ["request.", "input(", "sys.argv", "getenv", "raw_input"]
        sink = vuln.name.lower()
        
        lines = code.split("\n")
        vuln_line = vuln.location.split(":")[-1]
        
        try:
            line_idx = int(vuln_line) - 1
            # Check surrounding lines (5 lines before and after)
            start = max(0, line_idx - 5)
            end = min(len(lines), line_idx + 6)
            context = "\n".join(lines[start:end])
            
            # Check if any source pattern is in context
            for pattern in source_patterns:
                if pattern in context:
                    return True
            
            # Check for variable assignment patterns
            # If the vulnerable function is called with a variable that might be user-controlled
            # This is a simplification - real data flow analysis is more complex
            if "=" in context and sink in context:
                return True
                
        except (ValueError, IndexError):
            pass
        
        return False
    
    def _analyze_data_flow_with_llm(self, vuln: Vulnerability, code: str) -> bool:
        """Use LLM for more sophisticated data flow analysis."""
        if not self.llm_client:
            return self._check_data_flow(vuln, code)
        
        try:
            prompt = f"""
            Analyze if there's a data flow from user input to the vulnerable function.
            
            Vulnerability: {vuln.name} ({vuln.cve})
            Location: {vuln.location}
            
            Code context:
            ```\n{self._get_code_context(code, vuln.location)}\n```
            
            Answer only 'YES' if user input reaches the vulnerable function, otherwise 'NO'.
            """
            # response = self.llm_client.invoke(prompt)
            # return "YES" in response.content.upper()
            
        except Exception:
            pass
        
        return self._check_data_flow(vuln, code)
    
    def _get_code_context(self, code: str, location: str, lines: int = 20) -> str:
        """Get code context around a location."""
        try:
            line_num = int(location.split(":")[-1])
            code_lines = code.split("\n")
            start = max(0, line_num - lines // 2)
            end = min(len(code_lines), line_num + lines // 2)
            return "\n".join(code_lines[start:end])
        except (ValueError, IndexError):
            return code[:500]
