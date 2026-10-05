#!/usr/bin/env python3
"""Re-materialise the Juliet sources a manifest points at.

``datasets/`` is git-ignored, so a fresh clone (or a cleaned disk) has the
ground-truth *manifest* but none of the *code* it names: every path in
``datasets/eval_subset_600.json`` resolves to nothing, and Phase 1, Phase 2 and
the LLM leg all have nothing to read.  The corpus itself is still recoverable
from the Hugging Face LorenzH/juliet_test_suite_c_1_3 CSVs, whose ``bad`` and
``good`` columns are the already-split variants -- the same columns
``scripts/import_hf_juliet.py`` writes when it builds a manifest from scratch.

This script goes the other way: it takes a manifest that already exists and
writes back exactly the files it names, so the archived results become
re-runnable again.  Only the rows the manifest needs are read and written; the
train CSV alone is 237 MB and turns into ~160k files.

Usage:
    python scripts/restore_eval_corpus.py datasets/eval_subset_600.json

CSVs are located under ``--hf-cache`` (default: the user's huggingface hub
cache) and may be overridden with ``--train`` / ``--test``.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
from pathlib import Path
from typing import Dict

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

DEFAULT_HUB_CACHE = Path.home() / ".cache" / "huggingface" / "hub"
REPO = "datasets--LorenzH--juliet_test_suite_c_1_3"
TRAIN_BLOB = "312b94c0854d387608b95e9b466cc4548a39aa16f916128b0c22879493fd6940"
TEST_BLOB = "d0f8719b7e9fd1989053fa4991ed9a14ac4cd96737519eaf6dd3be50132d2b02"

_VARIANT_RE = re.compile(r"_(bad|good)$")


def original_filename(target: str) -> tuple[str, str] | None:
    """``..._bad.c`` -> ``(... .c, bad)``.

    ``None`` when the name is not a split variant: writing the original over a
    file that is not a good/bad pair would silently relabel it.
    """
    stem = Path(target).stem
    match = _VARIANT_RE.search(stem)
    if not match:
        return None
    suffix = Path(target).suffix
    return f"{stem[: match.start()]}{suffix}", match.group(1)


def wanted_rows(manifest: dict) -> Dict[str, list[tuple[str, str]]]:
    """Original basename -> [(target path, variant), ...] for every sample."""
    wanted: Dict[str, list[tuple[str, str]]] = {}
    for sample in manifest.get("samples", []):
        target = str(sample["file"])
        if not os.path.isabs(target):
            target = str(PROJECT_ROOT / target)
        pair = original_filename(target)
        if pair is None:
            continue
        original, variant = pair
        wanted.setdefault(original, []).append((target, variant))
    return wanted


def rows_from(csv_path: Path, wanted: Dict[str, list[tuple[str, str]]]) -> int:
    """Write every wanted variant found in one CSV; return how many were hit."""
    written = 0
    with csv_path.open(newline="", encoding="utf-8", errors="replace") as handle:
        for row in csv.DictReader(handle):
            name = str(row.get("filename") or "").rsplit("/", 1)[-1]
            targets = wanted.get(name)
            if not targets:
                continue
            for target, variant in targets:
                code = row.get(variant)
                if not isinstance(code, str) or not code.strip():
                    continue
                path = Path(target)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(code, encoding="utf-8")
                written += 1
            del wanted[name]
    return written


def load_csv_paths(args: argparse.Namespace) -> list[Path]:
    if args.train or args.test:
        return [p for p in (args.train, args.test) if p]
    blobs = DEFAULT_HUB_CACHE / REPO / "blobs"
    return [blobs / TRAIN_BLOB, blobs / TEST_BLOB]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", help="manifest whose source files are missing")
    parser.add_argument("--train", type=Path, help="path to jts_c_1_3_train.csv")
    parser.add_argument("--test", type=Path, help="path to jts_c_1_3_test.csv")
    args = parser.parse_args()

    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    wanted = wanted_rows(manifest)
    samples = manifest.get("samples", [])
    print(f"{len(samples)} samples -> {len(wanted)} distinct source files")

    written = 0
    for csv_path in load_csv_paths(args):
        if not csv_path.is_file():
            print(f"skipping {csv_path}: not found")
            continue
        before = len(wanted)
        written += rows_from(csv_path, wanted)
        print(f"{csv_path.name}: {before - len(wanted)} files matched, {len(wanted)} still missing")

    if wanted:
        missing = sorted(wanted)[:5]
        print(f"FAILED: {len(wanted)} files not in any CSV, e.g. {missing}")
        return 1

    print(f"restored {written}/{len(samples)} source files under {PROJECT_ROOT}/datasets/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
