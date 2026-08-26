from __future__ import annotations
import json
from pathlib import Path
from typing import Dict, Iterable, List
from .models import GroundTruth

class GroundTruthDataset:
    def __init__(self, samples: Iterable[GroundTruth], *, root: str | Path | None = None):
        self.samples = list(samples)
        self.root = Path(root).resolve() if root else None
        self._by_id: Dict[str, GroundTruth] = {s.sample_id: s for s in self.samples}

    @classmethod
    def from_json(cls, path: str | Path) -> "GroundTruthDataset":
        path = Path(path).resolve()
        payload = json.loads(path.read_text(encoding="utf-8"))
        items = payload.get("samples", payload if isinstance(payload, list) else [])
        if not isinstance(items, list): raise ValueError("Ground-truth JSON must contain a 'samples' list")
        samples: List[GroundTruth] = []
        for item in items:
            samples.append(GroundTruth(
                sample_id=str(item["sample_id"]), file=str(item["file"]), vulnerable=bool(item["vulnerable"]),
                cwe=[str(x) for x in item.get("cwe", [])],
                line=int(item["line"]) if item.get("line") is not None else None,
                function=item.get("function"), finding_id=item.get("finding_id"),
                description=str(item.get("description", "")),
                group_id=item.get("group_id"),
                variant=item.get("variant"),
                scenario=item.get("scenario"),
                language=item.get("language"),
            ))
        dataset_root = path.parent
        if isinstance(payload, dict):
            metadata = payload.get("dataset", {})
            if isinstance(metadata, dict) and metadata.get("root"):
                candidate = Path(str(metadata["root"]))
                if candidate.exists():
                    dataset_root = candidate.resolve()
        return cls(samples, root=dataset_root)

    def resolve_file(self, sample: GroundTruth) -> Path:
        p = Path(sample.file)
        return p if p.is_absolute() else (self.root / p if self.root else p)
    def __iter__(self): return iter(self.samples)
    def __len__(self): return len(self.samples)
