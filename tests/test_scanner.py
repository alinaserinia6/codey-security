#!/usr/bin/env python3
"""
Unit tests for the vulnerability scanner.
"""

import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

from core.parser import CodeParser
from core.scanner_agent import ScannerAgent
from core.verifier_agent import VerifierAgent
from main import VulnerabilityScanner

class TestCodeParser(unittest.TestCase):
    def setUp(self):
        self.parser = CodeParser()
    
    def test_parse_python(self):
        code = """
def hello(name):
    print(f"Hello {name}")

def main():
    hello("world")
"""
        result = self.parser.parse(code, "python")
        self.assertIn("functions", result)
        self.assertGreater(len(result["functions"]), 0)
    
    def test_parse_c(self):
        code = """
#include <stdio.h>
void hello(char *name) {
    printf("Hello %s", name);
}
int main() {
    hello("world");
    return 0;
}
"""
        result = self.parser.parse(code, "c")
        self.assertIn("functions", result)
        self.assertGreater(len(result["functions"]), 0)

class TestScannerAgent(unittest.TestCase):
    def setUp(self):
        self.scanner = ScannerAgent()
    
    def test_scan_python_vulnerabilities(self):
        code = """
from flask import request, render_template_string
@app.route('/render')
def render():
    template = request.form.get('template')
    return render_template_string(template)
"""
        parsed = {"file": "test.py"}
        results = self.scanner.scan(code, parsed, "python")
        self.assertGreater(len(results), 0)
        self.assertTrue(any("CVE-2021-25239" in str(r) for r in results))
    
    def test_scan_c_vulnerabilities(self):
        code = """
void copy(char *input) {
    char buffer[64];
    strcpy(buffer, input);
}
"""
        parsed = {"file": "test.c"}
        results = self.scanner.scan(code, parsed, "c")
        self.assertGreater(len(results), 0)
        self.assertTrue(any("CVE-2021-3156" in str(r) for r in results))

class TestVerifierAgent(unittest.TestCase):
    def setUp(self):
        self.verifier = VerifierAgent()
    
    def test_verify_vulnerability(self):
        from core.models import Vulnerability, Severity
        
        vuln = Vulnerability(
            cve="CVE-2021-25239",
            cwe="CWE-94",
            name="SSTI",
            description="Template injection",
            location="test.py:5",
            severity=Severity.CRITICAL,
            evidence="Found render_template_string",
            confirmed=False
        )
        
        code = """
from flask import request, render_template_string
@app.route('/render')
def render():
    template = request.form.get('template')
    return render_template_string(template)
"""
        parsed = {"file": "test.py"}
        results = self.verifier.verify([vuln], code, parsed)
        self.assertEqual(len(results), 1)
        # Should be confirmed because user input reaches the sink
        self.assertTrue(results[0].confirmed)

    def test_reject_when_no_source(self):
        """A sink with no reachable user input must not be confirmed."""
        from core.models import Vulnerability, Severity

        vuln = Vulnerability(
            cve="CVE-2021-3156",
            cwe="CWE-787",
            name="Heap Buffer Overflow",
            description="Buffer overflow",
            location="test.c:3",
            severity=Severity.CRITICAL,
            evidence="Found strcpy",
            confirmed=False
        )

        # strcpy copies a constant string; no tainted parameter or call.
        code = """
#include <string.h>
void copy(char *input) {
    char buffer[64];
    strcpy(buffer, "static");
}
int main(void) {
    copy("static");
    return 0;
}
"""
        parsed = {"file": "test.c"}
        results = self.verifier.verify([vuln], code, parsed)
        # Enclosing function has no tainted source and its call passes literals.
        self.assertFalse(results[0].confirmed)

    def test_confirm_via_tainted_call_argument(self):
        """C parameter taint: function called with argv reaches a sink."""
        from core.models import Vulnerability, Severity
        from core.parser import CodeParser

        code = """
#include <string.h>
void copy(char *input) {
    char buffer[64];
    strcpy(buffer, input);
}
int main(int argc, char **argv) {
    copy(argv[1]);
    return 0;
}
"""
        parser = CodeParser()
        parsed = parser.parse(code, "c")
        parsed["file"] = "test.c"

        vuln = Vulnerability(
            cve="CVE-2021-3156",
            cwe="CWE-787",
            name="Heap Buffer Overflow",
            description="Buffer overflow",
            location="test.c:4",
            severity=Severity.CRITICAL,
            evidence="Found strcpy",
            confirmed=False
        )
        results = self.verifier.verify([vuln], code, parsed)
        self.assertTrue(results[0].confirmed)

class TestIntegration(unittest.TestCase):
    @patch("config.Config.AI_API_KEY", "")
    def setUp(self):
        self.scanner = VulnerabilityScanner()
    
    def test_scan_sample_file(self):
        # Test with sample vulnerable Python file
        sample_path = Path(__file__).parent.parent / "samples" / "vulnerable_python.py"
        if sample_path.exists():
            report = self.scanner.scan_file(str(sample_path))
            self.assertGreater(len(report.vulnerabilities), 0)
            # Check that at least one vulnerability is confirmed
            confirmed = [v for v in report.vulnerabilities if v.confirmed]
            self.assertGreater(len(confirmed), 0)

if __name__ == "__main__":
    unittest.main()
