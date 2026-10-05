"""Compare two archived Phase-3 results file-by-file.

Two runs over the same corpus are a paired experiment, so the honest question
is not "do their confidence intervals overlap" but "how many files did they
disagree on".  This script rebuilds each run's predictions from its own stored
reports (or, for the LLM-only leg, from its stored finding set), re-scores both
with that run's own matching policy, and applies McNemar's test to the
per-sample decisions.

Nothing is re-run: no analyzer, no model, no new labels.  The output is the
discordance table itself first, because on a corpus with a handful of true
positives the number of disagreeing files is more informative than the
p-value derived from it.

Usage:
    python scripts/compare_paired.py results/exp_A_static_subset600.json \\
        results/exp_C_static_llm_subset600.json

    python scripts/compare_paired.py A.json C.json --json out/paired.json

The thesis's claim that configurations A--D cannot be ranked at 95% confidence
is exactly the claim this test is for; running it on every shipped pair turns
"cannot be proven" into a number.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import List

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from phase3.dataset import GroundTruthDataset  # noqa: E402
from phase3.significance import STRATA, paired_comparison  # noqa: E402

# ``scripts`` is not a package, so the recompute helper is loaded by path --
# the same way the tests load it -- rather than imported by name.
_spec = importlib.util.spec_from_file_location(
    "recompute_result",
    Path(__file__).resolve().parent / "recompute_result.py",
)
_recompute_result = importlib.util.module_from_spec(_spec)
sys.modules.setdefault("recompute_result", _recompute_result)
_spec.loader.exec_module(_recompute_result)
_recompute = _recompute_result.recompute


def _p(value: float) -> str:
    """Six decimals turn a real p-value into a bare zero, which reads as a
    stronger claim than the test made."""
    return f"{value:.1e}" if value < 0.0001 else f"{value:.4f}"


STRATUM_LABELS = {
    "positive_detection": "recall (vulnerable files)",
    "benign_flagging": "benign flag rate (clean files)",
    "accuracy": "accuracy (all files)",
}


def _label(payload: dict, fallback: str) -> str:
    provenance = (payload.get("metadata", {}) or {}).get("provenance", {}) or {}
    return str(provenance.get("label") or provenance.get("experiment")
               or payload.get("experiment") or fallback)


def _matcher_warnings(payloads: List[dict], names: List[str]) -> List[str]:
    """A paired test is only meaningful if both runs used the same matcher."""
    warnings: List[str] = []
    seen = {}
    for payload, name in zip(payloads, names):
        matching = (payload.get("metadata", {}) or {}).get("matching") or {}
        key = (
            matching.get("require_cwe_when_available"),
            matching.get("line_tolerance"),
        )
        seen.setdefault(key, []).append(name)
    if len(seen) > 1:
        detail = "; ".join(
            f"{', '.join(files)} -> require_cwe={cwe}, tolerance={tol}"
            for (cwe, tol), files in seen.items()
        )
        warnings.append(
            "the two runs were scored with different matching policies, so "
            f"their disagreement is partly the matcher: {detail}"
        )
    return warnings


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("result_a", help="first Phase-3 result JSON (baseline)")
    parser.add_argument("result_b", help="second Phase-3 result JSON (challenger)")
    parser.add_argument("--dataset",
                        help="override the dataset recorded in provenance")
    parser.add_argument("--method", choices=("exact", "chi2"), default="exact",
                        help="discordant-pair test (default: exact)")
    parser.add_argument("--json", help="write the full comparison to this file")
    args = parser.parse_args()

    names = [args.result_a, args.result_b]
    payloads: List[dict] = []
    for name in names:
        payloads.append(
            _recompute(Path(name),
                       Path(args.dataset) if args.dataset else None)
        )

    dataset_path = args.dataset
    if not dataset_path:
        provenance = (payloads[0].get("metadata", {}) or {}).get(
            "provenance", {}) or {}
        dataset_path = provenance.get("dataset")
        if not dataset_path:
            raise SystemExit("no dataset in provenance; pass --dataset")
    dataset = GroundTruthDataset.from_json(str(dataset_path))

    labels = [_label(payloads[0], "A"), _label(payloads[1], "B")]
    comparison = paired_comparison(payloads[0], payloads[1], list(dataset),
                                   method=args.method)

    print(f"\n=== {labels[0]}  vs  {labels[1]} ===")
    for warning in _matcher_warnings(payloads, names):
        print(f"  WARNING: {warning}")

    print(f"  {'stratum':<32}{'n':>5}{'rate A':>10}{'rate B':>10}"
          f"{'delta':>9}{'A only':>8}{'B only':>8}{'p':>10}")
    for name in STRATA:
        row = comparison["strata"][name]
        print(f"  {STRATUM_LABELS[name]:<32}{row['n']:>5}"
              f"{row['rate_a']:>10.3f}{row['rate_b']:>10.3f}"
              f"{row['delta_b_minus_a']:>+9.3f}"
              f"{row['b_a_only']:>8}{row['c_b_only']:>8}"
              f"{_p(row['p_value']):>10}")

    if comparison["identical"]:
        print("  the two runs made the same decision on every sample")

    if args.json:
        target = Path(args.json)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(
                {"a": labels[0], "b": labels[1], **comparison},
                indent=2, ensure_ascii=False,
            ) + "\n",
            encoding="utf-8",
        )
        print(f"  wrote {target}")


if __name__ == "__main__":
    main()
