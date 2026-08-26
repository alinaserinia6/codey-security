from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Iterable

from .parser import JulietFileParser, JulietSample


class JulietManifestBuilder:
    """Build a Codey Security ground-truth manifest from Juliet v1.3."""

    def __init__(self, root: str | Path, *, include_variants: Iterable[str] = ("bad", "good")) -> None:
        self.root = Path(root).resolve()
        self.testcases = self.root / "testcases"
        self.parser = JulietFileParser()
        self.include_variants = {v.lower() for v in include_variants}

    def build(
        self,
        *,
        cwes: Iterable[str] | None = None,
        max_samples: int | None = None,
        include_headers: bool = False,
    ) -> list[JulietSample]:
        if not self.testcases.is_dir():
            raise FileNotFoundError(f"Juliet testcases directory not found: {self.testcases}")

        wanted = {self._normalize_cwe(c) for c in cwes} if cwes else None
        samples: list[JulietSample] = []
        for path in sorted(self.testcases.rglob("*")):
            if not path.is_file():
                continue
            if not include_headers and path.suffix.lower() in {".h", ".hpp"}:
                continue
            parsed = self.parser.parse(path, root=self.root)
            if parsed is None or parsed.variant not in self.include_variants:
                continue
            if wanted and not (set(parsed.cwe) & wanted):
                continue
            samples.append(parsed)
            if max_samples is not None and len(samples) >= max_samples:
                break
        return samples

    def write_manifest(
        self,
        output: str | Path,
        *,
        cwes: Iterable[str] | None = None,
        max_samples: int | None = None,
        include_headers: bool = False,
    ) -> dict:
        samples = self.build(cwes=cwes, max_samples=max_samples, include_headers=include_headers)
        payload = {
            "dataset": {
                "name": "Juliet Test Suite for C/C++",
                "version": "1.3",
                "root": str(self.root),
                "testcases_root": "testcases",
                "ground_truth_policy": "filename variant: *_bad* => vulnerable, *_good* => non-vulnerable",
                "notes": [
                    "Samples are generated only from files under testcases/ matching Juliet naming conventions.",
                    "Ground truth is sample/file-level. Exact vulnerability lines may be populated when a bad/good function is detected.",
                    "Do not mix train/test splits by group_id; variants derived from the same Juliet scenario belong together.",
                ],
            },
            "samples": [
                {
                    "sample_id": s.sample_id,
                    "file": s.file,
                    "vulnerable": s.vulnerable,
                    "cwe": s.cwe,
                    "line": s.line,
                    "function": s.function,
                    "finding_id": f"JULIET-{s.sample_id}",
                    "description": f"Juliet {s.variant} sample ({s.cwe[0]})",
                    "group_id": s.group_id,
                    "variant": s.variant,
                    "scenario": s.scenario,
                    "language": s.language,
                }
                for s in samples
            ],
            "summary": self._summary(samples),
        }
        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return payload

    @staticmethod
    def _summary(samples: list[JulietSample]) -> dict:
        cwes = Counter(cwe for s in samples for cwe in s.cwe)
        variants = Counter(s.variant for s in samples)
        languages = Counter(s.language for s in samples)
        groups = len({s.group_id for s in samples})
        return {
            "samples": len(samples),
            "groups": groups,
            "variants": dict(sorted(variants.items())),
            "languages": dict(sorted(languages.items())),
            "cwes": dict(sorted(cwes.items())),
        }

    @staticmethod
    def _normalize_cwe(value: str) -> str:
        value = value.strip().upper()
        return value if value.startswith("CWE-") else f"CWE-{int(value.removeprefix('CWE'))}"
