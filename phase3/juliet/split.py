from __future__ import annotations

import json
import random
from collections import defaultdict
from pathlib import Path
from typing import Any


def split_manifest(
    manifest_path: str | Path,
    train_output: str | Path,
    test_output: str | Path,
    *,
    test_ratio: float = 0.2,
    seed: int = 42,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not 0.0 < test_ratio < 1.0:
        raise ValueError("test_ratio must be between 0 and 1")
    source = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    samples = list(source.get("samples", []))
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for sample in samples:
        group = str(sample.get("group_id") or sample["sample_id"])
        groups[group].append(sample)

    group_ids = sorted(groups)
    rng = random.Random(seed)
    rng.shuffle(group_ids)
    test_count = max(1, round(len(group_ids) * test_ratio)) if group_ids else 0
    test_groups = set(group_ids[:test_count])

    train_samples = [s for gid, items in groups.items() if gid not in test_groups for s in items]
    test_samples = [s for gid, items in groups.items() if gid in test_groups for s in items]

    def build(samples: list[dict[str, Any]], split: str) -> dict[str, Any]:
        payload = {
            "dataset": dict(source.get("dataset", {})),
            "split": {
                "name": split,
                "seed": seed,
                "test_ratio": test_ratio,
                "group_safe": True,
                "groups": sorted({str(s.get("group_id") or s["sample_id"]) for s in samples}),
            },
            "samples": samples,
            "summary": {
                "samples": len(samples),
                "vulnerable": sum(bool(s.get("vulnerable")) for s in samples),
                "benign": sum(not bool(s.get("vulnerable")) for s in samples),
            },
        }
        return payload

    train_payload = build(train_samples, "train")
    test_payload = build(test_samples, "test")
    Path(train_output).parent.mkdir(parents=True, exist_ok=True)
    Path(test_output).parent.mkdir(parents=True, exist_ok=True)
    Path(train_output).write_text(json.dumps(train_payload, indent=2) + "\n", encoding="utf-8")
    Path(test_output).write_text(json.dumps(test_payload, indent=2) + "\n", encoding="utf-8")
    return train_payload, test_payload
