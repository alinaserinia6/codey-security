"""Measure the source-to-sink evidence signal on a labelled dataset.

The taint tracker's value to the multi-agent design is not that it finds every
bug -- an intra-procedural engine cannot see a heap-size mismatch, and does not
claim to. Its value is that a chain it reports is a concrete, checkable path,
so the benign-file alarm rate can be pushed far below what pattern matching
alone achieves. This script produces the numbers that support that claim.

The proposal also requires the numbers to be comparable against the standard
tool for each language: Flawfinder for C and Bandit for Python. ``--baseline``
runs whichever applies and reports both side by side, because a low alarm rate
only means something next to the rate the existing tool achieves.

Usage:
    python scripts/eval_taint_evidence.py --dataset datasets/eval_subset_600.json
    python scripts/eval_taint_evidence.py \
        --dataset datasets/python_bench/python_bench.json \
        --baseline bandit --out results/exp_F_python_bench.json
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from analyzers.static_tools import BanditRunner, FlawfinderRunner  # noqa: E402
from analyzers.structural_analyzer import StructuralAnalyzer  # noqa: E402
from analyzers.taint import (  # noqa: E402
    SOURCE_PATTERNS,
    taint_chains_for,
    taint_language,
)

BASELINES = ("bandit", "flawfinder")
_BASELINE_RUNNERS = {
    "bandit": BanditRunner,
    "flawfinder": FlawfinderRunner,
}


def _load_samples(dataset: Path) -> List[Dict[str, Any]]:
    payload = json.loads(dataset.read_text(encoding="utf-8"))
    samples = payload.get("samples") if isinstance(payload, dict) else payload
    if not isinstance(samples, list):
        raise ValueError(f"{dataset} does not contain a list of samples")
    return samples


def _label(sample: Dict[str, Any]) -> str:
    cwe = sample.get("cwe")
    if isinstance(cwe, list) and cwe:
        return str(cwe[0])
    if isinstance(cwe, str) and cwe:
        return cwe
    return str(sample.get("scenario", "unknown"))


def _rates(tp: int, fp: int, fn: int, tn: int) -> Dict[str, Any]:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
        # The share of benign files that raised an alarm. The denominator is
        # every benign file, not just the ones that stayed quiet.
        "benign_flag_rate": round(fp / (fp + tn), 6) if (fp + tn) else 0.0,
    }


def _baseline_flag(
    name: str, path: Path, runner: Any, cache: Dict[str, Optional[bool]]
) -> Tuple[Optional[bool], Optional[str]]:
    """Run the language's standard tool once per file, caching the verdict.

    ``None`` means the tool did not produce a usable verdict. Callers must not
    score that sample as negative for the baseline: an unavailable tool is a
    missing measurement, not evidence that the file is benign.
    """
    key = str(path)
    if key in cache:
        return cache[key], None
    findings, errors = runner.scan(path)
    if errors:
        return None, "; ".join(errors)
    cache[key] = bool(findings)
    return cache[key], None


def evaluate(
    dataset: Path,
    limit: Optional[int] = None,
    baseline: Optional[str] = None,
) -> Dict[str, Any]:
    samples = _load_samples(dataset)
    if limit:
        samples = samples[:limit]
    if baseline and baseline not in BASELINES:
        raise ValueError(f"baseline must be one of {BASELINES}")

    analyzer = StructuralAnalyzer()
    runner: Any = _BASELINE_RUNNERS[baseline]() if baseline else None

    keys = ("tp", "fp", "fn", "tn")
    counts = {
        "taint_any": Counter(),
        "taint_unmitigated": Counter(),
        f"baseline_{baseline}": Counter() if baseline else Counter(),
        "union": Counter() if baseline else Counter(),
    }
    per_label_total: Counter = Counter()
    per_label_hit: Counter = Counter()
    sink_kinds: Counter = Counter()
    mitigations: Counter = Counter()
    failures: List[str] = []
    tool_errors: List[str] = []
    baseline_unavailable = 0
    baseline_cache: Dict[str, Optional[bool]] = {}

    def tally(counter: Counter, predicted: bool, vulnerable: bool) -> None:
        if vulnerable and predicted:
            counter["tp"] += 1
        elif vulnerable:
            counter["fn"] += 1
        elif predicted:
            counter["fp"] += 1
        else:
            counter["tn"] += 1

    per_language: Dict[str, Counter] = {}
    # A language the taint engine has no pattern table for yields no chains,
    # which is indistinguishable from "found nothing" once it is folded into
    # the totals: every such sample silently becomes a true negative. The
    # breakdown is recorded so that silence stays visible.
    unsupported: Counter = Counter()

    for sample in samples:
        raw = sample.get("file", "")
        path = Path(raw)
        if not path.is_absolute():
            # Manifests generated by phase3.loaders store paths relative to
            # the manifest's own directory, so they work on any checkout.
            path = dataset.parent / raw
        if not path.exists():
            counts["taint_any"]["missing"] += 1
            continue
        try:
            structure = analyzer.analyze_file(path)
            chains = taint_chains_for(structure)
        except Exception as error:  # noqa: BLE001 - one bad file must not stop the run
            failures.append(f"{path.name}: {type(error).__name__}: {error}")
            counts["taint_any"]["error"] += 1
            continue

        for chain in chains:
            if chain["source_expression"]:
                sink_kinds[chain["category"]] += 1
            if chain["mitigated"]:
                mitigations[chain["mitigation_rule"] or "unknown"] += 1

        has_path = any(chain["source_expression"] for chain in chains)
        unmitigated = any(
            chain["source_expression"] and not chain["mitigated"] for chain in chains
        )
        vulnerable = bool(sample.get("vulnerable"))
        label = _label(sample)

        tally(counts["taint_any"], has_path, vulnerable)
        tally(counts["taint_unmitigated"], unmitigated, vulnerable)

        language = str(sample.get("language") or structure.get("language") or "unknown")
        if taint_language(language) not in SOURCE_PATTERNS:
            unsupported[language] += 1
        language_counter = per_language.setdefault(language, Counter())
        language_counter["samples"] += 1
        tally(language_counter, unmitigated, vulnerable)

        if vulnerable:
            per_label_total[label] += 1
            per_label_hit[label] += unmitigated

        if baseline and runner is not None:
            flagged, error = _baseline_flag(baseline, path, runner, baseline_cache)
            if flagged is None:
                # A failed baseline scan is excluded from the baseline and
                # union tallies, but it is counted here and its message is
                # retained in tool_errors.
                baseline_unavailable += 1
                if len(tool_errors) < 10:
                    tool_errors.append(f"{path.name}: {error}")
            else:
                tally(counts[f"baseline_{baseline}"], flagged, vulnerable)
                tally(counts["union"], unmitigated or flagged, vulnerable)

    def block(name: str) -> Dict[str, Any]:
        counter = counts[name]
        return _rates(
            counter["tp"], counter["fp"], counter["fn"], counter["tn"]
        )

    result: Dict[str, Any] = {
        "dataset": str(dataset),
        "samples": len(samples),
        "parsed": sum(counts["taint_any"][k] for k in keys),
        "errors": counts["taint_any"]["error"],
        "missing": counts["taint_any"]["missing"],
        "failures": failures[:20],
        "metrics": {
            "any_source_to_sink_path": block("taint_any"),
            "source_to_sink_path_without_mitigation": block("taint_unmitigated"),
        },
        "per_cwe_recall": {
            label: {
                "detected": per_label_hit[label],
                "total": per_label_total[label],
                "recall": round(
                    per_label_hit[label] / per_label_total[label], 6
                )
                if per_label_total[label]
                else 0.0,
            }
            for label in sorted(per_label_total)
        },
        "sink_categories": dict(sink_kinds.most_common()),
        "mitigations_recognised": dict(mitigations.most_common()),
        "per_language": {
            language: {
                "samples": counter["samples"],
                **_rates(
                    counter["tp"], counter["fp"], counter["fn"], counter["tn"]
                ),
            }
            for language, counter in sorted(per_language.items())
        },
        "languages_without_evidence_support": dict(unsupported),
    }

    if baseline:
        result["baseline"] = {
            "tool": baseline,
            "metrics": block(f"baseline_{baseline}"),
            "tool_errors": tool_errors,
            "unavailable_samples": baseline_unavailable,
        }
        result["metrics"]["union_with_baseline"] = block("union")
    return result


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--dataset",
        type=Path,
        default=REPO_ROOT / "datasets" / "eval_subset_600.json",
        help="labelled dataset produced by phase3.dataset",
    )
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument(
        "--baseline",
        choices=BASELINES,
        default=None,
        help="run the language's standard tool for comparison (bandit/flawfinder)",
    )
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)

    result = evaluate(args.dataset, args.limit, args.baseline)
    text = json.dumps(result, indent=2, ensure_ascii=False)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
