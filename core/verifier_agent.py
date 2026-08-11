from typing import List, Dict, Any
from core.models import Vulnerability

class VerifierAgent:
    """
    Verifier Agent: Validates vulnerability hypotheses by checking data flow.
    If an LLM client is provided, uses LLM for sophisticated data flow analysis;
    otherwise falls back to simple heuristic.
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
            # Try LLM-based analysis first if available
            if self.llm_client:
                confirmed = self._analyze_data_flow_with_llm(vuln, code)
            else:
                confirmed = self._check_data_flow(vuln, code)
            
            if confirmed:
                vuln.confirmed = True
                vuln.evidence += " ✅ Verified: Data flow confirmed."
            else:
                vuln.evidence += " ❌ Rejected: No clear data flow."
            
            verified.append(vuln)
        
        return verified
    
    def _check_data_flow(self, vuln: Vulnerability, code: str) -> bool:
        """
        Simple heuristic: check if user input patterns exist near the vulnerability.
        """
        source_patterns = ["request.", "input(", "sys.argv", "getenv", "raw_input"]
        sink = vuln.name.lower()
        
        lines = code.split("\n")
        vuln_line = vuln.location.split(":")[-1]
        
        try:
            line_idx = int(vuln_line) - 1
            start = max(0, line_idx - 5)
            end = min(len(lines), line_idx + 6)
            context = "\n".join(lines[start:end])
            
            for pattern in source_patterns:
                if pattern in context:
                    return True
            
            if "=" in context and sink in context:
                return True
                
        except (ValueError, IndexError):
            pass
        
        return False
    
    def _analyze_data_flow_with_llm(self, vuln: Vulnerability, code: str) -> bool:
        """
        Use LLM to determine if there's a data flow from source to sink.
        """
        if not self.llm_client:
            return self._check_data_flow(vuln, code)
        
        try:
            # Get code context around the vulnerability location
            context = self._get_code_context(code, vuln.location, lines=30)
            
            prompt = f"""
            You are a security expert. Analyze the following code snippet and determine if user-controlled input can reach the vulnerable function.
            
            Vulnerability: {vuln.name} ({vuln.cve})
            CWE: {vuln.cwe}
            Description: {vuln.description}
            Location: {vuln.location}
            
            Code context: {context}
            Answer with only "YES" if user input reaches the vulnerable function, otherwise "NO".
            Provide no additional text.
            """

            # Call LLM (using LangChain or direct OpenAI API)
            if hasattr(self.llm_client, 'invoke'):
                response = self.llm_client.invoke(prompt)
                answer = response.content.strip().upper()
            else:
                # Fallback if client is a simple callable
                response = self.llm_client(prompt)
                answer = str(response).strip().upper()

            return "YES" in answer

        except Exception as e:
            print(f"LLM analysis failed for {vuln.cve}: {e}")
            # Fallback to heuristic
            return self._check_data_flow(vuln, code)

    def _get_code_context(self, code: str, location: str, lines: int = 20) -> str:
        """Extract context lines around the vulnerability location."""
        try:
            line_num = int(location.split(":")[-1])
            code_lines = code.split("\n")
            start = max(0, line_num - lines // 2)
            end = min(len(code_lines), line_num + lines // 2)
            # Add line numbers for context
            context_lines = []
            for i in range(start, end):
                context_lines.append(f"{i+1}: {code_lines[i]}")
            return "\n".join(context_lines)
        except (ValueError, IndexError):
            return code[:1000]  # fallback
