from __future__ import annotations

import csv
import io
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, List, Optional, Sequence
import xml.etree.ElementTree as ET

from .finding import Finding


class ToolRunner:
    def __init__(self, timeout: int = 120) -> None:
        self.timeout = timeout

    @staticmethod
    def available(command: str) -> bool:
        return shutil.which(command) is not None

    @staticmethod
    def _int_or_none(value: Optional[str]) -> Optional[int]:
        try:
            return int(value) if value else None
        except (TypeError, ValueError):
            return None

    def run(self, args: Sequence[str], cwd: Optional[Path] = None) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                list(args),
                cwd=str(cwd) if cwd else None,
                encoding="utf-8",
                errors="replace",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            # Synthesize a CompletedProcess so callers record an error
            # instead of aborting the whole file/benchmark on one slow tool.
            cmd = list(args)
            stdout = exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            stderr = (exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or ""))
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=124,
                stdout=stdout,
                stderr=f"{stderr}\ntool timed out after {self.timeout}s: {' '.join(cmd)}".strip(),
            )
        except OSError as exc:
            cmd = list(args)
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=127,
                stdout="",
                stderr=f"failed to launch {' '.join(cmd)}: {exc}",
            )


class BanditRunner(ToolRunner):
    """Python security scanner; produces normalized Findings from Bandit's JSON."""

    tool_name = "bandit"

    def scan(self, path: Path) -> tuple[List[Finding], List[str]]:
        if not self.available("bandit"):
            return [], ["bandit is not installed or not on PATH"]
        try:
            completed = self.run(["bandit", "-q", "-f", "json", "-r", str(path)])
        except Exception as exc:  # noqa: BLE001 - one tool must not stop a run
            return [], [f"bandit failed to run: {type(exc).__name__}: {exc}"]
        findings: List[Finding] = []
        errors: List[str] = []
        try:
            payload = json.loads(completed.stdout or "{}")
        except json.JSONDecodeError:
            out = completed.stdout or ""
            return [], [f"bandit returned non-JSON output: {out[-500:]}"]

        for item in payload.get("errors", []) or []:
            errors.append(f"bandit: {item}")

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

    # Findings whose severity is not security-relevant.
    _SKIPPED_SEVERITIES = {
        "information", "debug", "style", "performance", "portability",
    }

    _INFORMATIONAL_IDS = {
        "missingInclude", "missingIncludeSystem", "checkersReport",
        "unmatchedSuppression", "preprocessorErrorDirective",
    }

    _SYNTAX_NOISE_IDS = {
        "syntaxError", "unknownMacro", "badMacro", "unhandledException",
    }

    def scan(self, path: Path) -> tuple[List[Finding], List[str]]:
        if not self.available("cppcheck"):
            return [], ["cppcheck is not installed or not on PATH"]
        try:
            completed = self.run(
                ["cppcheck", "--xml", "--xml-version=2", "--enable=all", str(path)]
            )
        except Exception as exc:  # noqa: BLE001 - one tool must not stop a run
            return [], [f"cppcheck failed to run: {type(exc).__name__}: {exc}"]
        xml_text = completed.stderr or completed.stdout or ""
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

            if severity in self._SKIPPED_SEVERITIES:
                continue
            if rule_id in self._INFORMATIONAL_IDS:
                continue
            if rule_id in self._SYNTAX_NOISE_IDS:
                continue

            location = error.find("location")
            file_name = location.attrib.get("file") if location is not None else None
            line = self._int_or_none(location.attrib.get("line")) if location is not None else None
            column = self._int_or_none(location.attrib.get("column")) if location is not None else None

            # CWE: cppcheck 2.14+ emits the `cwe` attribute as a bare number
            # ("398"), older versions emit "CWE-398". That attribute is the
            # only trustworthy source: the human-readable message is full of
            # innocent numbers (years, sizes, array bounds) that must never
            # become CWE ids.
            cwe = self._extract_cwe(error.attrib.get("cwe", ""))

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
    def _extract_cwe(*texts: str) -> List[str]:
        """Normalize structured CWE attributes into ``CWE-<digits>`` ids.

        Only ever feed this the tool's dedicated CWE field (cppcheck's ``cwe``
        attribute, which is a bare number or ``CWE-`` prefixed). Prose such as
        the verbose message must not go through here: it contains years, array
        bounds and sizes that would otherwise be minted into fake CWEs.
        """
        result: List[str] = []
        for text in texts:
            if not text:
                continue
            # Split on common separators and normalize.
            normalized = (
                text.replace("!/", ",").replace(";", ",").replace("/", ",")
            )
            for token in normalized.split():
                for piece in token.split(","):
                    piece = piece.strip().upper().rstrip("!")
                    if not piece:
                        continue
                    if piece.startswith("CWE-"):
                        digits = piece[4:]
                    elif piece.isdigit():
                        # cppcheck 2.14+ emits bare CWE numbers.
                        digits = piece
                    else:
                        continue
                    if digits.isdigit():
                        result.append(f"CWE-{int(digits)}")
        return sorted(set(result))


class FlawfinderRunner(ToolRunner):
    tool_name = "flawfinder"

    # Flawfinder rules that produce style-class noise on Juliet-sized code.
    # These fire on any fixed-size array or benign helper call without
    # evidence of an actual overflow, and overwhelm real findings.
    _NOISE_RULES = {
        # Declaration heuristics — fire on any sized array.
        "char",
        "wchar_t",
        "TCHAR",
        "LPCWSTR",
        "LPCSTR",
        "LPTSTR",
        "LPSTR",
        # Informational-only rules — no exploit path, no relevance.
        "strlen",
        "wcslen",
        "atoi",
        # Generic safe-API usage rules — the "safe" alternative is flagged.
        "snprintf",
        "vsnprintf",
        "_snprintf",
        "swprintf",
        "strncpy",
        "wcsncpy",
        "strncat",
        "wcsncat",
        # Memory primitives that are flagged on nearly every call.
        "memcpy",
        "memmove",
        "memset",
        "MultiByteToWideChar",
        "WideCharToMultiByte",
    }

    def scan(self, path: Path) -> tuple[List[Finding], List[str]]:
        if not self.available("flawfinder"):
            return [], ["flawfinder is not installed or not on PATH"]
        try:
            completed = self.run(["flawfinder", "--csv", str(path)])
        except Exception as exc:  # noqa: BLE001 - one tool must not stop a run
            return [], [f"flawfinder failed to run: {type(exc).__name__}: {exc}"]
        findings: List[Finding] = []
        errors: List[str] = []
        if completed.returncode not in (0, 1):
            # On failure stdout is not a CSV report (usage text, a traceback
            # fragment, ...), and DictReader would happily turn that into
            # phantom findings.
            return [], [
                f"flawfinder exited with {completed.returncode}: "
                f"{completed.stderr.strip()}"
            ]
        try:
            reader = csv.DictReader(io.StringIO(completed.stdout))
            for row in reader:
                rule_name = (row.get("Name") or "").strip()
                if rule_name in self._NOISE_RULES:
                    continue

                findings.append(
                    Finding(
                        tool=self.tool_name,
                        rule_id=rule_name or "unknown",
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

        return findings, errors

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
        `CWE-119!/CWE-120`, and it also appends a trailing `!` to the whole
        cell (`CWE-362/CWE-367!`). It also occasionally uses `;` or `,` as
        separators. Normalize all of these to validated `CWE-<digits>` ids:
        anything else (a stray `!`, prose) is dropped, not minted.
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
            token = token.strip().upper().rstrip("!")
            if not token.startswith("CWE-"):
                continue
            digits = token[4:]
            if digits.isdigit():
                result.append(f"CWE-{int(digits)}")
        return sorted(set(result))

