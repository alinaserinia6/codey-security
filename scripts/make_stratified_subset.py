#!/usr/bin/env python3
"""Build a stratified evaluation subset from any labelled manifest.

LLM experiments cost one model call per file, so a full run over a large
manifest is several hours. This script draws a reproducible *stratified*
subset: the sample count per (primary CWE, vulnerable) stratum is fixed, and
the selection inside a stratum is driven by ``--seed``. Stratifying on the
label keeps the positive and negative populations balanced, which is what
makes the false-positive rate meaningful.

Every experiment (A/B/C/D) is then run on exactly the same subset, so the
comparison table is not confounded by different populations.

Usage:
    python scripts/make_stratified_subset.py \
        --dataset datasets/vulnllm_r_c.json \
        --out datasets/eval_subset.json \
        --per-stratum 150 --seed 42
"""
from __future__ import annotations

import argparse
import collections
import json
import random
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from phase3.dataset import GroundTruthDataset  # noqa: E402


def _primary_cwe(sample: dict) -> str:
    cwes = sample.get("cwe") or []
    return str(cwes[0]) if cwes else "none"


def build_subset(dataset: Path, per_stratum: int, seed: int, *, require_file: bool):
    samples = json.loads(dataset.read_text(encoding="utf-8")).get("samples", [])
    resolved = GroundTruthDataset.from_json(dataset)

    keep = []
    for sample, ground_truth in zip(samples, resolved):
        if require_file and not resolved.resolve_file(ground_truth).exists():
            continue
        keep.append(sample)

    strata: dict[tuple[str, bool], list[dict]] = collections.defaultdict(list)
    for sample in keep:
        strata[(_primary_cwe(sample), bool(sample["vulnerable"]))].append(sample)

    rng = random.Random(seed)
    selected = []
    for key in sorted(strata, key=lambda k: (k[0], k[1])):
        group = sorted(strata[key], key=lambda s: str(s["sample_id"]))
        rng.shuffle(group)
        selected.extend(group[:per_stratum])

    # Restore dataset order so runs are not grouped by stratum.
    order = {str(s["sample_id"]): i for i, s in enumerate(keep)}
    selected.sort(key=lambda s: order[str(s["sample_id"])])

    payload = {
        "dataset": {
            "name": f"stratified-subset-of-{dataset.stem}",
            "source": str(dataset.resolve()),
            "per_stratum": per_stratum,
            "seed": seed,
        },
        "samples": selected,
    }
    return payload, strata


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--per-stratum", type=int, default=150)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--allow-missing-files",
        action="store_true",
        help="keep samples whose source file is absent (they become failures)",
    )
    args = parser.parse_args()

    payload, strata = build_subset(
        Path(args.dataset), args.per_stratum, args.seed,
        require_file=not args.allow_missing_files,
    )
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    counts = collections.Counter(
        (_primary_cwe(s), bool(s["vulnerable"])) for s in payload["samples"]
    )
    print(f"Wrote {len(payload['samples'])} samples to {out}")
    for key in sorted(counts):
        print(f"  {key[0]:<10} vulnerable={str(key[1]):<5} n={counts[key]}")
    print(f"Strata available in source: {len(strata)}")


if __name__ == "__main__":
    main()
