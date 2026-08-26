#!/usr/bin/env python3
from __future__ import annotations
import argparse
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description="Unified Codey Security pipeline CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p1 = sub.add_parser("phase1", help="Run deterministic structural/static analysis")
    p1.add_argument("path")
    p1.add_argument("--out", required=False)

    args = parser.parse_args()
    if args.command == "phase1":
        from analyzers.phase1_pipeline import Phase1Pipeline
        result = Phase1Pipeline().analyze_path(args.path)
        text = json.dumps(result, indent=2, ensure_ascii=False)
        if args.out:
            Path(args.out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.out).write_text(text + "\n", encoding="utf-8")
            print(f"Report written to {args.out}")
        else:
            print(text)


if __name__ == "__main__":
    main()
