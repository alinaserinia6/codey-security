from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from phase3.juliet.split import split_manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Create group-safe train/test manifests from a Juliet manifest.")
    parser.add_argument("manifest")
    parser.add_argument("--train-out", default="datasets/juliet_1.3_train.json")
    parser.add_argument("--test-out", default="datasets/juliet_1.3_test.json")
    parser.add_argument("--test-ratio", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    train, test = split_manifest(args.manifest, args.train_out, args.test_out, test_ratio=args.test_ratio, seed=args.seed)
    print(json.dumps({"train": train["summary"], "test": test["summary"], "seed": args.seed}, indent=2))


if __name__ == "__main__":
    main()
