from __future__ import annotations

import sys
import argparse
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from phase3.juliet.manifest import JulietManifestBuilder


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a Codey Security ground-truth manifest from Juliet C/C++ 1.3.")
    parser.add_argument("juliet_root", help="Path to the Juliet repository/archive root containing testcases/")
    parser.add_argument("--out", default="datasets/juliet_1.3_manifest.json")
    parser.add_argument("--cwe", action="append", dest="cwes", help="Restrict to a CWE; repeat this option for multiple CWEs")
    parser.add_argument("--max-samples", type=int, default=None)
    parser.add_argument("--include-headers", action="store_true")
    args = parser.parse_args()

    builder = JulietManifestBuilder(args.juliet_root)
    payload = builder.write_manifest(
        args.out,
        cwes=args.cwes,
        max_samples=args.max_samples,
        include_headers=args.include_headers,
    )
    print(json.dumps(payload["summary"], indent=2))
    print(f"Manifest written to {Path(args.out).resolve()}")


if __name__ == "__main__":
    main()
