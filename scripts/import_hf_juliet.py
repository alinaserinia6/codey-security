#!/usr/bin/env python3
"""Materialize the Hugging Face Juliet dataset into a Codey-Security manifest.

Reads the LorenzH/juliet_test_suite_c_1_3 CSVs via pandas, writes each
good/bad snippet to a real source file under datasets/juliet_hf/, and emits
train/test manifests matching dataset_schema.json.

Usage:
    python scripts/import_hf_juliet.py --split all
    python scripts/import_hf_juliet.py --split train --cwe CWE-120
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Dict, Hashable, List, Mapping, Optional

import pandas as pd

# HF_BASE = "hf://datasets/LorenzH/juliet_test_suite_c_1_3/"
HF_BASE = "datasets/LorenzH/juliet_test_suite_c_1_3/"
HF_FILES = {
    "train": "jts_c_1_3_train.csv",
    "test":  "jts_c_1_3_test.csv",
}

# CWE120_Buffer_Copy_Large_String__strcpy_01.c  -> CWE-120 and group id.
FILENAME_RE = re.compile(
    r"^(?P<cwe>CWE\d+)_(?P<name>.+?)__(?P<variant>[A-Za-z0-9_]+?)_(?P<flow>\d{2})"
    r"\.(?P<ext>c|cpp)$"
)


def _cwe_from_path(p: str) -> List[str]:
    """Prefer the directory name; fall back to the file name."""
    for part in Path(p).parts:
        m = re.match(r"^(CWE\d+)", part)
        if m:
            return [f"CWE-{int(m.group(1)[3:])}"]
    return []


def _language_from_name(name: str) -> str:
    lower = name.lower()
    if lower.endswith((".c", ".h")):
        return "c"
    if lower.endswith((".cpp", ".cc", ".cxx", ".hpp", ".hxx")):
        return "cpp"
    return "unknown"


def _group_id_from_name(name: str) -> str:
    """Strip the trailing _01.._18 flow number so variants share a group."""
    stem = Path(name).stem
    return re.sub(r"_\d{2}$", "", stem)


def _safe_slug(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", name)


def _write_source(root: Path, rel_dir: str, fname: str, code: str) -> str:
    """Write code to disk and return the path relative to `root`."""
    target = root / rel_dir / _safe_slug(fname)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(code, encoding="utf-8")
    return str(target.relative_to(root))


def _row_to_samples(
    row: Mapping[Hashable, Any],
    split_root: Path,
) -> List[Dict[str, Any]]:
    """Turn one HF row into up to two manifest samples (bad + good)."""
    filename = str(row.get("filename") or row.get("file") or "")
    if not filename:
        return []

    cwe = _cwe_from_path(filename)
    language = _language_from_name(filename)
    group_id = _group_id_from_name(filename)
    stem = Path(filename).stem
    subdir = Path(filename).parent.name  # e.g. "CWE120_Buffer_Copy_Large_String"

    out: List[Dict[str, Any]] = []

    bad_code = row.get("bad")
    if isinstance(bad_code, str) and bad_code.strip():
        rel = _write_source(split_root, subdir, f"{stem}_bad{Path(filename).suffix}", bad_code)
        out.append({
            "sample_id": f"{group_id}__bad",
            "file": rel,
            "vulnerable": True,
            "cwe": cwe,
            "line": None,
            "function": "bad",
            "group_id": group_id,
            "variant": "bad",
            "scenario": group_id,
            "language": language,
            "description": f"HF bad variant of {filename}",
        })

    good_code = row.get("good")
    if isinstance(good_code, str) and good_code.strip():
        rel = _write_source(split_root, subdir, f"{stem}_good{Path(filename).suffix}", good_code)
        out.append({
            "sample_id": f"{group_id}__good",
            "file": rel,
            "vulnerable": False,
            "cwe": cwe,
            "line": None,
            "function": "good",
            "group_id": group_id,
            "variant": "good",
            "scenario": group_id,
            "language": language,
            "description": f"HF good variant of {filename}",
        })

    return out


def build_manifest(
    split: str,
    out_dir: Path,
    *,
    cwe_filter: Optional[str] = None,
    max_samples: Optional[int] = None,
) -> Dict[str, Any]:
    url = HF_BASE + HF_FILES[split]
    print(f"Loading {url}")
    df = pd.read_csv(url)

    if cwe_filter:
        wanted = cwe_filter.upper().replace("-", "")
        df = df[df["filename"].str.contains(f"{wanted}_", case=False, na=False)]
        print(f"Filtered to {len(df)} rows for {cwe_filter}")

    split_root = out_dir / f"juliet_hf_{split}"
    split_root.mkdir(parents=True, exist_ok=True)

    samples: List[Dict[str, Any]] = []
    for _, row in df.iterrows():
        samples.extend(_row_to_samples(row.to_dict(), split_root))
        if max_samples and len(samples) >= max_samples:
            samples = samples[:max_samples]
            break

    vulnerable = sum(1 for s in samples if s["vulnerable"])
    manifest = {
        "dataset": {
            "name": f"juliet-c-cpp-1.3-hf-{split}",
            "root": str(split_root.resolve()),
            "source": f"huggingface://LorenzH/juliet_test_suite_c_1_3/{HF_FILES[split]}",
            "sample_count": len(samples),
            "vulnerable_count": vulnerable,
            "benign_count": len(samples) - vulnerable,
        },
        "samples": samples,
    }

    out_path = out_dir / f"juliet_hf_{split}.json"
    out_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(
        f"{split}: wrote {len(samples)} samples "
        f"({vulnerable} vulnerable / {len(samples) - vulnerable} benign) -> {out_path}"
    )
    return manifest


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--split", choices=["train", "test", "all"], default="all")
    p.add_argument("--out-dir", default="datasets")
    p.add_argument("--cwe", help="Optional CWE filter, e.g. CWE-120")
    p.add_argument("--max-samples", type=int, default=None)
    args = p.parse_args()

    out_dir = Path(args.out_dir)
    splits = ["train", "test"] if args.split == "all" else [args.split]
    for split in splits:
        build_manifest(
            split,
            out_dir,
            cwe_filter=args.cwe,
            max_samples=args.max_samples,
        )


if __name__ == "__main__":
    main()
