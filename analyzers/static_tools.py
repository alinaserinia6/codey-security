from __future__ import annotations

import csv
import io
import json
import plistlib
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence
import xml.etree.ElementTree as ET

from .finding import Finding


class ToolRunner:
    def __init__(self, timeout: int = 120) -> None:
        self.timeout = timeout

    @staticmethod
    def available(command: str) -> bool:
        return shutil.which(command) is not None

    def run(self, args: Sequence[str], cwd: Optional[Path] = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            list(args),
            cwd=str(cwd) if cwd else None,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=self.timeout,
            check=False,
        )


class BanditRunner(ToolRunner):
    """Python security scanner; produces normalized Findings from Bandit's JSON."""

    tool_name = "bandit"

    def scan(self, path: Path) -> tuple[List[Finding], List[str]]:
        if not self.available("bandit"):
            return [], ["bandit is not installed or not on PATH"]
        completed = self.run(["bandit", "-q", "-f", "json", "-r", str(path)])
        findings: List[Finding] = []
        errors: List[str] = []
        try:
            payload = json.loads(completed.stdout or "{}")
        except json.JSONDecodeError:
            return [], [f"bandit returned non-JSON output: {completed.stdout[-500:]}"]

        for item in payload.get("results", []):
            cwe_node = item.get("issue_cwe")
            cwe: List[str] = []
            if isinstance(cwe_node, dict):
                cwe_id = cwe_node.get("id")
                if cwe_id is not None:
                    cwe = [f"CWE-{cwe_id}"]

            findings.append(
                Finding(
                    tool=self.tool_name,
                    rule_id=str(item.get("test_id", "B000")),
                    message=str(item.get("issue_text", "")),
                    file=item.get("filename"),
                    line=item.get("line_number"),
                    column=item.get("col_offset"),
                    severity=str(item.get("issue_severity", "UNKNOWN")),
                    confidence=self._confidence(item.get("issue_confidence")),
                    cwe=cwe,
                    evidence=item.get("code"),
                    raw=item,
                )
            )
        if completed.returncode not in (0, 1):
            errors.append(f"bandit exited with {completed.returncode}: {completed.stderr.strip()}")
        return findings, errors

    @staticmethod
    def _confidence(value: Any) -> Optional[float]:
        if isinstance(value, (int, float)):
            return float(value)
        mapping = {"LOW": 0.33, "MEDIUM": 0.66, "HIGH": 1.0}
        return mapping.get(str(value).upper())


class CppcheckRunner(ToolRunner):
    tool_name = "cppcheck"

    # Cppcheck routinely emits informational messages that are not security
    # findings. Filter them out before they reach Phase 2.
    _INFORMATIONAL_IDS = {
        "missingInclude",
        "missingIncludeSystem",
        "checkersReport",
        "unmatchedSuppression",
        "preprocessorErrorDirective",
    }
    _INFORMATIONAL_SEVERITIES = {"information", "debug"}

    def scan(self, path: Path) -> tuple[List[Finding], List[str]]:
        if not self.available("cppcheck"):
            return [], ["cppcheck is not installed or not on PATH"]
        completed = self.run(
            ["cppcheck", "--xml", "--xml-version=2", "--enable=all", str(path)]
        )
        xml_text = completed.stderr or completed.stdout
        findings: List[Finding] = []
        errors: List[str] = []
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return [], [f"cppcheck returned invalid XML: {xml_text[-1000:]}"]

        errors_node = root.find("errors")
        if errors_node is None:
            return [], []

        for error in errors_node.findall("error"):
            rule_id = error.attrib.get("id", "unknown")
            severity = error.attrib.get("severity", "").lower()
            if severity in self._INFORMATIONAL_SEVERITIES:
                continue
            if rule_id in self._INFORMATIONAL_IDS:
                continue

            location = error.find("location")
            file_name = location.attrib.get("file") if location is not None else None
            line = self._int_or_none(location.attrib.get("line")) if location is not None else None
            column = self._int_or_none(location.attrib.get("column")) if location is not None else None
            cwe = self._extract_cwe(error.attrib.get("cwe", ""), error.attrib.get("verbose", ""))

            findings.append(
                Finding(
                    tool=self.tool_name,
                    rule_id=rule_id,
                    message=error.attrib.get("verbose", error.attrib.get("msg", "")),
                    file=file_name,
                    line=line,
                    column=column,
                    severity=error.attrib.get("severity", "UNKNOWN"),
                    cwe=cwe,
                    category=rule_id,
                    evidence=error.attrib.get("msg"),
                    raw=error.attrib,
                )
            )
        if completed.returncode not in (0, 1):
            errors.append(f"cppcheck exited with {completed.returncode}: {completed.stdout[-500:]}")
        return findings, errors

    @staticmethod
    def _int_or_none(value: Optional[str]) -> Optional[int]:
        try:
            return int(value) if value else None
        except ValueError:
            return None

    @staticmethod
    def _extract_cwe(*texts: str) -> List[str]:
        result: List[str] = []
        for text in texts:
            normalized = (
                text.replace("!/", ",")
                .replace(";", ",")
                .replace("/", ",")
                .replace(":", " ")
            )
            for token in normalized.split():
                for piece in token.split(","):
                    piece = piece.strip().upper()
                    if piece.startswith("CWE-"):
                        result.append(piece)
        return sorted(set(result))


class FlawfinderRunner(ToolRunner):
    tool_name = "flawfinder"

    def scan(self, path: Path) -> tuple[List[Finding], List[str]]:
        if not self.available("flawfinder"):
            return [], ["flawfinder is not installed or not on PATH"]
        completed = self.run(["flawfinder", "--csv", str(path)])
        findings: List[Finding] = []
        errors: List[str] = []
        try:
            reader = csv.DictReader(io.StringIO(completed.stdout))
            for row in reader:
                findings.append(
                    Finding(
                        tool=self.tool_name,
                        rule_id=row.get("Name") or "unknown",
                        message=row.get("Warning") or "",
                        file=row.get("File") or None,
                        line=self._int_or_none(row.get("Line")),
                        column=self._int_or_none(row.get("Column")),
                        severity=self._risk_to_severity(row.get("Level")),
                        cwe=self._split_cwes(row.get("CWEs")),
                        category=row.get("Category"),
                        evidence=row.get("Context"),
                        suggestion=row.get("Suggestion"),
                        raw=row,
                    )
                )
        except csv.Error as exc:
            return [], [f"flawfinder CSV parsing failed: {exc}"]

        if completed.returncode not in (0, 1):
            errors.append(f"flawfinder exited with {completed.returncode}: {completed.stderr.strip()}")
        return findings, errors

    @staticmethod
    def _int_or_none(value: Optional[str]) -> Optional[int]:
        try:
            return int(value) if value else None
        except ValueError:
            return None

    @staticmethod
    def _risk_to_severity(value: Optional[str]) -> str:
        try:
            risk = int(value or 0)
        except ValueError:
            return "UNKNOWN"
        if risk >= 5:
            return "CRITICAL"
        if risk >= 4:
            return "HIGH"
        if risk >= 2:
            return "MEDIUM"
        if risk == 1:
            return "LOW"
        return "UNKNOWN"

    @staticmethod
    def _split_cwes(value: Optional[str]) -> List[str]:
        """Split Flawfinder's CWEs column into individual identifiers.

        Flawfinder encodes "or" with `!/`, so a cell can read
        `CWE-119!/CWE-120`. It also occasionally uses `;` or `,` as
        separators. Normalize all of these to a single delimiter.
        """
        if not value:
            return []
        normalized = (
            value.replace("!/", ",")
            .replace(";", ",")
            .replace("/", ",")
        )
        result = []
        for token in normalized.split(","):
            token = token.strip().upper()
            if token.startswith("CWE-"):
                result.append(token)
        return sorted(set(result))


class ClangStaticAnalyzerRunner(ToolRunner):
    """
    Run Clang Static Analyzer through scan-build for a standalone translation unit.

    For complete projects, prefer feeding scan-build the real build command or a
    compile_commands.json-driven integration; this standalone mode is the Phase-1
    baseline and keeps the runner usable on individual benchmark files.
    """

    tool_name = "clang-static-analyzer"

    def scan(self, path: Path, compiler: Optional[str] = None) -> tuple[List[Finding], List[str]]:
        if not self.available("scan-build"):
            return [], ["scan-build is not installed or not on PATH"]

        if compiler is None:
            compiler = "clang++" if path.suffix.lower() in {".cc", ".cpp", ".cxx", ".hpp", ".hxx"} else "clang"

        if not self.available(compiler):
            return [], [f"{compiler} is not installed or not on PATH"]

        findings: List[Finding] = []
        errors: List[str] = []
        with tempfile.TemporaryDirectory(prefix="fake-scan-build-") as temp_dir:
            out_dir = Path(temp_dir) / "reports"
            command = [
                "scan-build",
                "-plist",
                "-o",
                str(out_dir),
                compiler,
                "-fsyntax-only",
                str(path),
            ]
            completed = self.run(command)
            plist_files = list(out_dir.rglob("*.plist")) if out_dir.exists() else []
            for plist_file in plist_files:
                findings.extend(self._parse_plist(plist_file))

            if completed.returncode not in (0, 1):
                errors.append(
                    f"scan-build exited with {completed.returncode}: "
                    f"{completed.stderr[-1000:] or completed.stdout[-1000:]}"
                )
        return findings, errors

    def _parse_plist(self, path: Path) -> List[Finding]:
        with path.open("rb") as handle:
            payload = plistlib.load(handle)

        findings: List[Finding] = []
        for diagnostic in payload.get("diagnostics", []):
            message = diagnostic.get("description") or diagnostic.get("problem", "Clang analyzer finding")
            location = diagnostic.get("location") or {}
            file_name = location.get("file")
            line = location.get("line")
            column = location.get("col")
            findings.append(
                Finding(
                    tool=self.tool_name,
                    rule_id=str(diagnostic.get("check_name", diagnostic.get("category", "unknown"))),
                    message=str(message),
                    file=file_name,
                    line=int(line) if isinstance(line, int) else None,
                    column=int(column) if isinstance(column, int) else None,
                    severity="HIGH",
                    cwe=[],
                    category=diagnostic.get("category"),
                    evidence=message,
                    raw=diagnostic,
                )
            )
        return findings
