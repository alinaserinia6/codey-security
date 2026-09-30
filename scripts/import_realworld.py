#!/usr/bin/env python3
"""Materialize a real-world Hugging Face vulnerability corpus into a manifest.

The old LorenzH Juliet mirror this project used is synthetic template code and
its snippets carry no compilable context, which is why so many of its files
score nothing under the static tools. PrimeVul and Big-Vul are real project
code with NVD-backed CWE labels and an explicit vulnerable/fixed split, so a
manifest built from them has the benign population a false-positive rate
needs.

The script reads either a local file or a Hugging Face dataset file and writes
one source file per function plus a Phase 3 manifest in dataset_schema.json
shape (good/bad separated, CWE-labelled, group-aware)::

    # PrimeVul paired test: 435 vulnerable + 435 fixed, 62 CWEs (default)
    python scripts/import_realworld.py --corpus primevul

    # Big-Vul test split: vulnerable func_before + fixed func_after twins
    python scripts/import_realworld.py --corpus bigvul

    # From an already-downloaded file, filtered to the proposal CWEs
    python scripts/import_realworld.py --corpus primevul --input /tmp/pv.jsonl \\
        --cwe CWE-122 --cwe CWE-190 --limit 200

    # VulnLLM-R function-level tests, grouped by CWE on disk (default)
    python scripts/import_realworld.py --corpus vulnllm-r

    # VulnLLM-R repo-level C tests (multi-function contexts + stack traces)
    python scripts/import_realworld.py --corpus vulnllm-r-repo

    # Refresh the download URLs when the upstream repo changes its shards
    python scripts/import_realworld.py --corpus bigvul --hf-file <url-or-path>

Manifest ``file`` entries are stored relative to the manifest's own directory,
so the checked-in manifests work on any checkout.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import urllib.request
from pathlib import Path
from typing import List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from phase3.loaders import (  # noqa: E402
    LoaderError,
    RealWorldOptions,
    VulnLLMROptions,
    load_bigvul_hf,
    load_primevul,
    load_vulnllm_r,
    write_manifest,
)

DEFAULTS = {
    "primevul": {
        "repo": "starsofchance/PrimeVul",
        # Paired test split: each vulnerable function next to its fix, with
        # NVD-verified CWE + CVE metadata. ~6 MB.
        "file": "primevul_test_paired.jsonl",
        "manifest": "datasets/primevul_test_paired.json",
    },
    "bigvul": {
        "repo": "bstee615/bigvul",
        # Test split: 33,050 rows (1,026 vulnerable), 85 CWEs. ~38 MB.
        # The hash suffix changes when upstream re-exports; pass --hf-file to
        # override without editing this script.
        "file": "data/test-00000-of-00001-d20b0e7149fa6eeb.parquet",
        "manifest": "datasets/bigvul_test.json",
    },
    "vulnllm-r": {
        "repo": "UCSB-SURFI/VulnLLM-R-Test-Data",
        # Function-level test set: 11,801 rows (C/Python/Java), 68 CWEs,
        # LLM-assisted human validation. ~4.5 MB.
        "file": "data/function_level-00000-of-00001.parquet",
        "manifest": "datasets/vulnllm_r_c.json",
    },
    "vulnllm-r-repo": {
        "repo": "UCSB-SURFI/VulnLLM-R-Test-Data",
        # Repo-level test set: 714 rows (C/Java) with multi-function context
        # and stack traces. ~4.2 MB.
        "file": "data/repo_level-00000-of-00001.parquet",
        "manifest": "datasets/vulnllm_r_repo_c.json",
    },
}

LOADERS = {
    "primevul": load_primevul,
    "bigvul": load_bigvul_hf,
    "vulnllm-r": load_vulnllm_r,
    "vulnllm-r-repo": load_vulnllm_r,
}


def download_hf_file(repo: str, path: str, dest: Path) -> Path:
    """Fetch one dataset file, preferring the ``hf`` CLI, else plain HTTPS."""
    if path.startswith(("http://", "https://")):
        url = path
    else:
        url = f"https://huggingface.co/datasets/{repo}/resolve/main/{path}"
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        proc = subprocess.run(
            ["hf", "download", repo, "--type", "dataset", "--include", path,
             "--local-dir", str(dest.parent)],
            capture_output=True,
            text=True,
            timeout=600,
        )
        candidate = dest.parent / path
        if proc.returncode == 0 and candidate.is_file():
            if candidate.resolve() != dest.resolve():
                candidate.rename(dest)
            return dest
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    print(f"downloading {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "codey-security"})
    with urllib.request.urlopen(req, timeout=600) as response, open(dest, "wb") as out:
        out.write(response.read())
    return dest


def build(args: argparse.Namespace) -> Path:
    defaults = DEFAULTS[args.corpus]
    manifest_path = Path(args.out or defaults["manifest"])
    if args.out_dir:
        out_dir = Path(args.out_dir)
    elif args.corpus.startswith("vulnllm-r"):
        # One shared CWE-grouped tree; each manifest references its slice.
        out_dir = manifest_path.parent / "vulnllm_r"
    else:
        out_dir = manifest_path.with_name(manifest_path.stem + "_functions")

    if args.input:
        corpus_file = Path(args.input)
    else:
        cache = REPO_ROOT / "data" / "raw" / args.corpus
        hf_file = args.hf_file or defaults["file"]
        dest = cache / Path(hf_file).name
        if dest.is_file() and not args.refresh:
            print(f"reusing cached {dest}")
            corpus_file = dest
        else:
            corpus_file = download_hf_file(defaults["repo"], hf_file, dest)

    if args.corpus.startswith("vulnllm-r"):
        split = "repo_level" if args.corpus == "vulnllm-r-repo" else "function_level"
        options = VulnLLMROptions(
            languages=args.language or (["c"] if split == "repo_level" else ["c", "python"]),
            split=split,
            cwe_filter=args.cwe,
            limit=args.limit,
            balanced=not args.no_balanced,
            seed=args.seed,
            relative_to=manifest_path.parent,
        )
    else:
        options = RealWorldOptions(
            cwe_filter=args.cwe,
            limit=args.limit,
            balanced=not args.no_balanced,
            seed=args.seed,
            relative_to=manifest_path.parent,
            include_fix_as_benign=not args.no_fix_twin,
        )
    try:
        payload = LOADERS[args.corpus](
            corpus_file, options=options, out_dir=out_dir
        )
    except LoaderError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(2) from error

    path = write_manifest(payload, manifest_path)
    meta = payload["dataset"]
    print(json.dumps(
        {k: meta[k] for k in (
            "name", "source", "sample_count", "vulnerable_count",
            "benign_count", "skipped_empty", "skipped_no_cwe",
        ) if k in meta}, indent=2))
    top = sorted(payload["dataset"].get("per_cwe", {}).items(),
                 key=lambda kv: kv[1], reverse=True)[:10]
    print("top CWEs:", ", ".join(f"{k}={v}" for k, v in top))
    print(f"\nmanifest written to {path}")
    print(f"functions in {out_dir} (0 empty: the loader refuses to write any)")
    return path


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--corpus", choices=sorted(LOADERS), default="primevul")
    parser.add_argument("--input", type=Path, default=None,
                        help="local .jsonl/.parquet/.csv/.json corpus file")
    parser.add_argument("--hf-file", default=None,
                        help="HF file path or full URL to download instead")
    parser.add_argument("--refresh", action="store_true",
                        help="re-download even if a cached copy exists")
    parser.add_argument("--out", default=None, help="manifest output path")
    parser.add_argument("--out-dir", default=None, help="function sources directory")
    parser.add_argument("--cwe", action="append", default=None,
                        help="keep only this CWE; repeatable")
    parser.add_argument("--limit", type=int, default=None,
                        help="cap on total samples after balancing")
    parser.add_argument("--no-balanced", action="store_true",
                        help="keep the natural class ratio instead of balancing")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--no-fix-twin", action="store_true",
                        help="bigvul: skip emitting func_after as benign twin")
    parser.add_argument("--language", action="append", default=None,
                        help="vulnllm-r: score only this language; repeatable "
                             "(default: c and python; repo split: c)")
    args = parser.parse_args(argv)
    build(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
