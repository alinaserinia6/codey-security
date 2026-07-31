#!/usr/bin/env python3
"""
Multi-Agent Code Vulnerability Scanner
Main entry point for the tool.
"""

import sys
import json
import argparse
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any

from core.parser import CodeParser
from core.scanner_agent import ScannerAgent
from core.verifier_agent import VerifierAgent
from core.models import AnalysisReport, Vulnerability
from config import Config

class VulnerabilityScanner:
    """Main orchestrator for the vulnerability scanning system."""
    
    def __init__(self):
        self.parser = CodeParser()
        self.scanner = ScannerAgent()
        self.verifier = VerifierAgent()
        self.results = []
    
    def scan_file(self, file_path: str) -> AnalysisReport:
        """Scan a single file for vulnerabilities."""
        path = Path(file_path)
        if not path.exists():
            return AnalysisReport(
                file_path=file_path,
                language="unknown",
                vulnerabilities=[],
                summary={"error": "File not found"}
            )
        
        # Determine language from extension
        ext = path.suffix.lower()
        lang_map = {
            ".py": "python",
            ".c": "c",
            ".h": "c",
        }
        language = lang_map.get(ext, "unknown")
        
        if language == "unknown":
            return AnalysisReport(
                file_path=file_path,
                language="unknown",
                vulnerabilities=[],
                summary={"error": f"Unsupported file type: {ext}"}
            )
        
        # Read and parse code
        try:
            code = path.read_text(encoding="utf-8")
        except Exception as e:
            return AnalysisReport(
                file_path=file_path,
                language=language,
                vulnerabilities=[],
                summary={"error": f"Failed to read file: {e}"}
            )
        
        parsed = self.parser.parse(code, language)
        parsed["file"] = file_path
        
        # Scan for vulnerabilities
        vulnerabilities = self.scanner.scan(code, parsed, language)
        
        # Verify vulnerabilities
        verified = self.verifier.verify(vulnerabilities, code, parsed)
        
        # Generate report
        report = AnalysisReport(
            file_path=file_path,
            language=language,
            vulnerabilities=verified,
            summary=self._generate_summary(verified)
        )
        
        return report
    
    def scan_directory(self, directory: str, recursive: bool = True) -> List[AnalysisReport]:
        """Scan all supported files in a directory."""
        path = Path(directory)
        if not path.exists() or not path.is_dir():
            return []
        
        reports = []
        extensions = [".py", ".c", ".h"]
        
        if recursive:
            files = [f for f in path.rglob("*") if f.suffix in extensions]
        else:
            files = [f for f in path.iterdir() if f.suffix in extensions]
        
        for file_path in files:
            print(f"Scanning: {file_path}")
            report = self.scan_file(str(file_path))
            reports.append(report)
        
        return reports
    
    def _generate_summary(self, vulnerabilities: List[Vulnerability]) -> Dict:
        """Generate summary statistics for a report."""
        total = len(vulnerabilities)
        confirmed = sum(1 for v in vulnerabilities if v.confirmed)
        
        severity_counts = {}
        for v in vulnerabilities:
            severity_counts[v.severity] = severity_counts.get(v.severity, 0) + 1
        
        return {
            "total_findings": total,
            "confirmed": confirmed,
            "unconfirmed": total - confirmed,
            "by_severity": severity_counts
        }
    
    def save_report(self, report: AnalysisReport, output_dir: str = None):
        """Save a report to a JSON file."""
        output_dir = output_dir or Config.OUTPUT_DIR
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = Path(report.file_path).stem
        output_file = Path(output_dir) / f"{filename}_{timestamp}.json"
        
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(report.model_dump(), f, indent=2, default=str)
        
        print(f"Report saved to: {output_file}")
        return output_file
    
    def print_report(self, report: AnalysisReport):
        """Print a human-readable report."""
        print("\n" + "=" * 60)
        print(f"📊 Vulnerability Report: {report.file_path}")
        print(f"   Language: {report.language}")
        print("=" * 60)
        
        if report.summary.get("error"):
            print(f"❌ Error: {report.summary['error']}")
            return
        
        print(f"\n📈 Summary:")
        print(f"   Total findings: {report.summary['total_findings']}")
        print(f"   ✅ Confirmed: {report.summary['confirmed']}")
        print(f"   ❌ Unconfirmed: {report.summary['unconfirmed']}")
        
        if report.summary.get("by_severity"):
            print(f"\n   By severity:")
            for severity, count in report.summary["by_severity"].items():
                print(f"      {severity}: {count}")
        
        if report.vulnerabilities:
            print("\n🔍 Detailed Findings:")
            for i, vuln in enumerate(report.vulnerabilities, 1):
                status = "✅" if vuln.confirmed else "⚠️"
                print(f"\n   {i}. {status} {vuln.name} ({vuln.cve})")
                print(f"      CWE: {vuln.cwe}")
                print(f"      Location: {vuln.location}")
                print(f"      Severity: {vuln.severity}")
                print(f"      Evidence: {vuln.evidence[:100]}...")
        else:
            print("\n✅ No vulnerabilities found.")
        
        print("\n" + "=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="Multi-Agent Code Vulnerability Scanner"
    )
    parser.add_argument(
        "target",
        help="File or directory to scan"
    )
    parser.add_argument(
        "-r", "--recursive",
        action="store_true",
        help="Scan directories recursively"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output directory for reports"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output"
    )
    
    args = parser.parse_args()
    
    scanner = VulnerabilityScanner()
    target = Path(args.target)
    
    if target.is_file():
        report = scanner.scan_file(str(target))
        scanner.print_report(report)
        if args.output:
            scanner.save_report(report, args.output)
    
    elif target.is_dir():
        reports = scanner.scan_directory(str(target), args.recursive)
        for report in reports:
            scanner.print_report(report)
            if args.output:
                scanner.save_report(report, args.output)
    
    else:
        print(f"Error: {target} does not exist.")
        sys.exit(1)


if __name__ == "__main__":
    main()
