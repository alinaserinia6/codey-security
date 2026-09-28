"""Build a Phase 3 manifest from a public labelled corpus.

    python scripts/make_manifest.py sard --root datasets/sard --out datasets/sard.json
    python scripts/make_manifest.py devign --input datasets/devign.json \\
        --out datasets/devign_manifest.json
    python scripts/make_manifest.py big-vul --input datasets/big-vul.json \\
        --out datasets/big_vul_manifest.json

The output is the same manifest format the Juliet and Python generators produce,
so every measurement script works over all of them unchanged.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from phase3.loaders import (  # noqa: E402
    FunctionCorpusOptions,
    LoaderError,
    SardOptions,
    load_big_vul,
    load_devign,
    load_sard,
    write_manifest,
)

CORPORA = ("sard", "devign", "big-vul")


def build(args: argparse.Namespace):
    if args.corpus == "sard":
        if not args.root:
            raise LoaderError("--root is required for sard")
        options = SardOptions(
            label_from=args.label_from,
            extensions=tuple(args.extension),
            assume_vulnerable=args.assume_vulnerable,
        )
        payload = load_sard(args.root, options, max_samples=args.limit)
    else:
        if not args.input:
            raise LoaderError(f"--input is required for {args.corpus}")
        options = FunctionCorpusOptions()
        if args.language:
            options.language = args.language
        if args.suffix:
            options.suffix = args.suffix
        loader = load_devign if args.corpus == "devign" else load_big_vul
        # Functions are written next to the manifest rather than into a default
        # location inside the repository, so a conversion cannot quietly scatter
        # extracted sources among the real corpora.
        out_dir = args.out_dir or args.out.with_name(args.out.stem + "_functions")
        payload = loader(
            args.input, options=options, out_dir=out_dir, max_samples=args.limit
        )
    return payload


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("corpus", choices=CORPORA)
    parser.add_argument("--root", type=Path, help="SARD release root directory")
    parser.add_argument("--input", type=Path, help="Devign/Big-Vul JSON file")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--out-dir", type=Path, default=None,
        help="where to write function-level sources (Devign/Big-Vul)",
    )
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument(
        "--label-from", choices=("directory", "metadata"), default="directory",
        help="how a SARD test case is labelled; 'metadata' requires metadata.csv",
    )
    parser.add_argument(
        "--extension", action="append", default=None,
        help="file extension to include, repeatable (default .c .cpp .cc .cxx .py)",
    )
    parser.add_argument(
        "--assume-vulnerable", action="store_true",
        help="sard: treat a test case sitting directly in a CWE directory as "
             "vulnerable, for releases that put only benign cases in a good/ "
             "subdirectory. Off by default, because getting this wrong would "
             "invert the benchmark's precision.",
    )
    parser.add_argument("--language", default=None, help="override the language")
    parser.add_argument("--suffix", default=None, help="override the written suffix")
    args = parser.parse_args(argv)
    if args.extension is None:
        args.extension = [".c", ".cpp", ".cc", ".cxx", ".py"]

    try:
        payload = build(args)
    except LoaderError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    path = write_manifest(payload, args.out)
    meta = payload["dataset"]
    print(json.dumps({k: meta[k] for k in sorted(meta) if k != "limitations"}, indent=2))
    print(f"\nmanifest written to {path}")
    if meta.get("unclassified_count"):
        print(
            f"warning: {meta['unclassified_count']} file(s) had no recognisable "
            "label and were left out; check --label-from or --assume-vulnerable",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
