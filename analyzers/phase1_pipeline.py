from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from .finding import NormalizedReport, correlate_findings, deduplicate_findings
from .static_tools import BanditRunner, ClangStaticAnalyzerRunner, CppcheckRunner, FlawfinderRunner
from .structural_analyzer import C_EXTENSIONS, CPP_EXTENSIONS, PYTHON_EXTENSIONS, StructuralAnalyzer


class Phase1Pipeline:
    """Deterministic Phase-1 analysis pipeline for Python and C/C++."""

    def __init__(self, timeout: int = 120) -> None:
        self.structural = StructuralAnalyzer()
        self.bandit = BanditRunner(timeout=timeout)
        self.cppcheck = CppcheckRunner(timeout=timeout)
        self.flawfinder = FlawfinderRunner(timeout=timeout)
        self.clang = ClangStaticAnalyzerRunner(timeout=timeout)

    def analyze_file(
        self,
        path: str | Path,
        *,
        run_bandit: bool = True,
        run_cppcheck: bool = True,
        run_flawfinder: bool = True,
        run_clang: bool = True,
    ) -> Dict[str, Any]:
        source_path = Path(path).resolve()
        language = self.structural.detect_language(source_path)
        report = NormalizedReport(source=str(source_path), language=language)

        structural = self.structural.analyze_file(source_path)
        report.metadata["structure"] = structural

        if language == "python":
            if run_bandit:
                findings, errors = self.bandit.scan(source_path)
                report.findings.extend(findings)
                report.errors.extend(errors)
        elif language in {"c", "cpp"}:
            if run_cppcheck:
                findings, errors = self.cppcheck.scan(source_path)
                report.findings.extend(findings)
                report.errors.extend(errors)
            if run_flawfinder:
                findings, errors = self.flawfinder.scan(source_path)
                report.findings.extend(findings)
                report.errors.extend(errors)
            if run_clang:
                findings, errors = self.clang.scan(source_path)
                report.findings.extend(findings)
                report.errors.extend(errors)

        report.findings = deduplicate_findings(report.findings)
        report.metadata["correlated_findings"] = correlate_findings(report.findings)
        report.metadata["tool_count"] = len({f.tool for f in report.findings})
        report.metadata["finding_count"] = len(report.findings)
        report.metadata["tool_status"] = self._tool_status(language)
        return report.to_dict()

    def analyze_path(self, path: str | Path) -> Dict[str, Any]:
        path_obj = Path(path).resolve()
        if path_obj.is_file():
            return self.analyze_file(path_obj)

        reports: List[Dict[str, Any]] = []
        for item in self.structural.analyze_path(path_obj, recursive=True):
            if "error" in item:
                reports.append(item)
                continue
            reports.append(self.analyze_file(item["path"]))
        return {
            "root": str(path_obj),
            "reports": reports,
            "summary": {
                "files": len(reports),
                "findings": sum(len(r.get("findings", [])) for r in reports if isinstance(r, dict)),
            },
        }

    def _tool_status(self, language: str) -> Dict[str, bool]:
        if language == "python":
            return {"bandit": self.bandit.available("bandit")}
        return {
            "cppcheck": self.cppcheck.available("cppcheck"),
            "flawfinder": self.flawfinder.available("flawfinder"),
            "scan-build": self.clang.available("scan-build"),
        }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run deterministic Phase-1 structural and static analysis.")
    parser.add_argument("path", help="Python/C/C++ file or source directory")
    parser.add_argument("--out", help="Write JSON report to this file")
    parser.add_argument("--no-bandit", action="store_true")
    parser.add_argument("--no-cppcheck", action="store_true")
    parser.add_argument("--no-flawfinder", action="store_true")
    parser.add_argument("--no-clang", action="store_true")
    return parser


def main() -> None:
    args = _build_parser().parse_args()
    pipeline = Phase1Pipeline()

    if Path(args.path).is_file():
        result = pipeline.analyze_file(
            args.path,
            run_bandit=not args.no_bandit,
            run_cppcheck=not args.no_cppcheck,
            run_flawfinder=not args.no_flawfinder,
            run_clang=not args.no_clang,
        )
    else:
        result = pipeline.analyze_path(args.path)

    rendered = json.dumps(result, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(rendered + "\n", encoding="utf-8")
        print(f"Report written to {args.out}")
    else:
        print(rendered)


if __name__ == "__main__":
    main()
