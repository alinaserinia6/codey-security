from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

C_EXTENSIONS = {".c"}
CPP_EXTENSIONS = {".cc", ".cpp", ".cxx", ".c++", ".h", ".hpp"}

_FILENAME_RE = re.compile(
    r"^(?P<cwe>CWE(?P<cwe_num>\d+))_(?P<rest>.+?)_(?P<variant>bad|good)(?P<suffix>[A-Za-z0-9_]*)\.(?P<ext>c|cc|cpp|cxx|c\+\+)$",
    re.IGNORECASE,
)
_CWE_PREFIX_RE = re.compile(r"^CWE(?P<num>\d+)_", re.IGNORECASE)
_SARD_ID_RE = re.compile(r"__(?P<body>[^.]+)", re.IGNORECASE)
_FUNCTION_RE = re.compile(
    r"(?m)^\s*[A-Za-z_][\w\s\*:&<>~]*\s+(?P<name>[A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{"
)


@dataclass(frozen=True)
class JulietSample:
    sample_id: str
    file: str
    vulnerable: bool
    cwe: list[str]
    variant: str
    group_id: str
    function: Optional[str] = None
    line: Optional[int] = None
    scenario: Optional[str] = None
    language: str = "c"

    def to_dict(self) -> dict:
        return asdict(self)


class JulietFileParser:
    """Parse Juliet C/C++ v1.3 filenames and source-level metadata.

    Juliet test cases are organized by CWE and distinguish buggy/good code.
    This parser deliberately uses conservative filename rules so helper files
    under testcasesupport are not treated as labeled test cases.
    """

    def parse(self, path: str | Path, *, root: str | Path | None = None) -> Optional[JulietSample]:
        p = Path(path)
        if p.suffix.lower() not in C_EXTENSIONS | CPP_EXTENSIONS:
            return None
        match = _FILENAME_RE.match(p.name)
        if not match:
            return None

        cwe = f"CWE-{int(match.group('cwe_num'))}"
        variant = match.group("variant").lower()
        language = "cpp" if p.suffix.lower() in CPP_EXTENSIONS else "c"
        relative = p.resolve().relative_to(Path(root).resolve()) if root else p
        rel = relative.as_posix()
        sample_id = rel.rsplit("/", 1)[-1]
        group_id = self._group_id(p.name)
        scenario = self._scenario(p.name)

        function, line = self._find_bad_function(p) if variant == "bad" else (None, None)
        if function is None and variant == "good":
            function, line = self._find_good_function(p)

        return JulietSample(
            sample_id=sample_id,
            file=rel,
            vulnerable=variant == "bad",
            cwe=[cwe],
            variant=variant,
            group_id=group_id,
            function=function,
            line=line,
            scenario=scenario,
            language=language,
        )

    def _find_bad_function(self, path: Path) -> tuple[Optional[str], Optional[int]]:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None, None
        candidates = list(_FUNCTION_RE.finditer(text))
        for m in candidates:
            name = m.group("name")
            if re.search(r"_bad(?:$|\d|[A-Z])", name, re.IGNORECASE) or name.lower().endswith("bad"):
                return name, text.count("\n", 0, m.start()) + 1
        return None, None

    def _find_good_function(self, path: Path) -> tuple[Optional[str], Optional[int]]:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None, None
        for m in _FUNCTION_RE.finditer(text):
            name = m.group("name")
            if "good" in name.lower():
                return name, text.count("\n", 0, m.start()) + 1
        return None, None

    @staticmethod
    def _group_id(filename: str) -> str:
        # Remove the final _bad/_good... token, preserving the CWE/scenario.
        stem = Path(filename).stem
        stem = re.sub(r"_(?:bad|good)[A-Za-z0-9_]*$", "", stem, flags=re.IGNORECASE)
        return stem

    @staticmethod
    def _scenario(filename: str) -> str | None:
        # Preserve the part after the double underscore when present.
        m = _SARD_ID_RE.search(Path(filename).stem)
        if m:
            return re.sub(r"_(?:bad|good)[A-Za-z0-9_]*$", "", m.group("body"), flags=re.IGNORECASE)
        return None
