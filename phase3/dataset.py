"""Loading of labelled benchmark corpora into :class:`GroundTruth` records."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List

from .models import GroundTruth


class GroundTruthDataset:
    """A corpus of labelled samples plus the root their paths are relative to."""

    def __init__(
        self, samples: Iterable[GroundTruth], *, root: str | Path | None = None
    ) -> None:
        self.samples = list(samples)
        self.root = Path(root).resolve() if root else None
        self._by_id: Dict[str, GroundTruth] = {s.sample_id: s for s in self.samples}

    @classmethod
    def from_json(cls, path: str | Path) -> "GroundTruthDataset":
        path = Path(path).resolve()
        payload = json.loads(path.read_text(encoding="utf-8"))
        items = payload.get("samples", payload if isinstance(payload, list) else [])
        if not isinstance(items, list):
            raise ValueError("Ground-truth JSON must contain a 'samples' list")

        samples: List[GroundTruth] = [
            GroundTruth(
                sample_id=str(item["sample_id"]),
                file=str(item["file"]),
                vulnerable=bool(item["vulnerable"]),
                cwe=[str(x) for x in item.get("cwe", [])],
                line=int(item["line"]) if item.get("line") is not None else None,
                function=item.get("function"),
                finding_id=item.get("finding_id"),
                description=str(item.get("description", "")),
                group_id=item.get("group_id"),
                variant=item.get("variant"),
                scenario=item.get("scenario"),
                language=item.get("language"),
            )
            for item in items
        ]

        return cls(samples, root=cls._dataset_root(path, payload))

    @staticmethod
    def _dataset_root(path: Path, payload: Any) -> Path:
        """Resolve the directory that relative sample paths are based on."""
        candidate_root = path.parent
        if isinstance(payload, dict):
            metadata = payload.get("dataset", {})
            if isinstance(metadata, dict) and metadata.get("root"):
                candidate = Path(str(metadata["root"]))
                if candidate.exists():
                    candidate_root = candidate.resolve()
        return candidate_root

    def resolve_file(self, sample: GroundTruth) -> Path:
        path = Path(sample.file)
        if path.is_absolute():
            return path
        return self.root / path if self.root else path

    def get(self, sample_id: str) -> GroundTruth | None:
        return self._by_id.get(sample_id)

    def languages(self) -> List[str]:
        return sorted({s.language for s in self.samples if s.language})

    def __iter__(self):
        return iter(self.samples)

    def __len__(self) -> int:
        return len(self.samples)

    def __repr__(self) -> str:
        return f"GroundTruthDataset(samples={len(self.samples)}, root={self.root})"
