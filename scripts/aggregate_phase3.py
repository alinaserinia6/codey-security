from __future__ import annotations

import argparse
import sys
from pathlib import Path

# The script lives in scripts/, so the repository root is not importable until
# it is put on the path explicitly.
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from phase3.aggregate import load_results, summary_rows, write_csv  # noqa: E402


def main():
    p = argparse.ArgumentParser(
        description="Compare Phase-3 experiment result JSON files"
    )
    p.add_argument("results", nargs="+", help="phase3 result JSON files")
    p.add_argument("--csv", default="phase3_comparison.csv")
    args = p.parse_args()

    results = load_results(args.results)
    rows = summary_rows(results)
    headers = [
        "experiment", "TP", "FP", "FN", "TN",
        "precision", "recall", "f1", "fpr", "specificity",
        "accuracy", "balanced_accuracy",
    ]
    print("\t".join(headers))
    for row in rows:
        print("\t".join(str(row[h]) for h in headers))
    write_csv(results, args.csv)
    print(f"CSV written to {args.csv}")


if __name__ == "__main__":
    main()
