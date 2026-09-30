#!/usr/bin/env python3
"""Derive a focused manifest from an existing one without touching sources.

Writes a new manifest that references the same files (paths are unchanged, so
the new manifest must live in the same directory as the original)::

    python scripts/filter_manifest.py --in datasets/vulnllm_r_c.json \\
        --out datasets/vulnllm_r_c_dataflow.json \\
        --cwe CWE-78 --cwe CWE-787 --cwe CWE-125 --cwe CWE-119 --cwe CWE-120

Counts, per-CWE stats and the digest are recomputed; the ``dataset`` metadata
records the filter so the derivation stays auditable.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def canonical_cwe(value: str) -> str:
    digits = "".join(ch for ch in value if ch.isdigit())
    return f"CWE-{int(digits)}" if digits else value


def build(args: argparse.Namespace) -> Path:
    src = Path(args.in_path)
    payload = json.loads(src.read_text(encoding="utf-8"))
    samples = payload.get("samples", [])
    wanted = {canonical_cwe(c) for c in (args.cwe or [])}
    langs = {l.lower() for l in (args.language or [])}

    kept: List[dict] = []
    for sample in samples:
        cwes = [canonical_cwe(c) for c in sample.get("cwe", [])]
        if wanted and not (set(cwes) & wanted):
            continue
        if langs and str(sample.get("language", "")).lower() not in langs:
            continue
        kept.append(sample)

    if not kept:
        raise SystemExit("error: filter kept 0 samples")
    if args.limit is not None and len(kept) > args.limit:
        kept = kept[:args.limit]

    # Rebase `file` entries to the new manifest's directory: the source may
    # live anywhere, but readers resolve relative paths against the manifest
    # that contains them. Absolute entries are left untouched.
    out = Path(args.out)
    for sample in kept:
        raw = sample.get("file", "")
        candidate = Path(raw)
        if raw and not candidate.is_absolute():
            sample["file"] = os.path.relpath(src.parent / raw, out.parent)

    per_cwe: dict = {}
    for sample in kept:
        for cwe in sample.get("cwe", []) or []:
            per_cwe[cwe] = per_cwe.get(cwe, 0) + 1
    digest = hashlib.sha256(
        "\n".join(sorted(s["sample_id"] for s in kept)).encode()
    ).hexdigest()[:16]

    base = dict(payload.get("dataset", {}))
    base.update({
        "name": base.get("name", src.stem) + "+filtered",
        "derived_from": str(src),
        "cwe_filter": sorted(wanted) if wanted else None,
        "language_filter": sorted(langs) if langs else None,
        "sample_count": len(kept),
        "vulnerable_count": sum(1 for s in kept if s.get("vulnerable")),
        "benign_count": sum(1 for s in kept if not s.get("vulnerable")),
        "per_cwe": dict(sorted(per_cwe.items())),
        "digest": digest,
    })
    out.write_text(json.dumps({"dataset": base, "samples": kept}, indent=2) + "\n")
    print(json.dumps(
        {k: base[k] for k in ("sample_count", "vulnerable_count",
                              "benign_count", "cwe_filter")}, indent=2))
    print(f"manifest written to {out} ({len(kept)} samples, files shared, none copied)")
    return out


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--in", dest="in_path", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--cwe", action="append", default=None,
                        help="keep samples with this CWE; repeatable")
    parser.add_argument("--language", action="append", default=None,
                        help="keep only this language; repeatable")
    parser.add_argument("--limit", type=int, default=None,
                        help="cap total samples after filtering (stable order)")
    args = parser.parse_args(argv)
    build(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
