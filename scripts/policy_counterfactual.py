"""Score archived Phase-2 runs under alternative decision policies.

The shipped report keeps only ``CONFIRMED`` groups (see
``phase3.extract_predictions.predictions_from_phase2``), which is what makes
the false-positive reduction possible -- and what costs recall.  Every verdict
the agent actually produced is still sitting in ``metadata.reports`` of the
archived result, so the price of that filter can be measured exactly instead of
being argued about: rebuild the prediction set under a different policy and
re-run the same matcher.  No model call, no Phase-1 re-run, no new labels.

Three things come out of one pass over a result file:

* **policy table** -- precision/recall/FPR/accuracy with Wilson 95% intervals
  for each verdict policy, so a "keep the uncertain ones" proposal is
  quantified rather than asserted;
* **miss decomposition** -- every ground-truth positive attributed to the
  stage that lost it: the candidate generator never proposed it, the agent
  stayed silent, the verdict was UNCERTAIN, the verdict was REJECTED, or the
  confirmation lost to the matching policy.  This is the difference between a
  system that filters too hard and a system that never looked;
* **triage queue** -- the UNCERTAIN verdicts ranked by confidence, for the
  human-review lane that recovers recall without touching the main report.

Usage:
    python scripts/policy_counterfactual.py results/exp_C_static_llm_subset600.json
    python scripts/policy_counterfactual.py results/*.json --json out/policies.json
    python scripts/policy_counterfactual.py results/exp_C_...json \\
        --triage-dir results/triage

A leg that stores no Phase-2 reports (the LLM-only baseline scores straight
from its verdicts) has no policies to counterfactually score; such files are
reported as such instead of silently producing an empty table.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from phase3.dataset import GroundTruthDataset  # noqa: E402
from phase3.evaluator import evaluate  # noqa: E402
from phase3.extract_predictions import (  # noqa: E402
    CONFIRMED,
    REJECTED,
    UNCERTAIN,
    predictions_from_phase1,
    predictions_from_phase2,
)
from phase3.matcher import MatchConfig  # noqa: E402
from phase3.models import Prediction  # noqa: E402

#: Named verdict policies, in the order they are reported.  ``shipped`` is the
#: shipped behaviour and is always scored first so every other row is a delta
#: against it.
POLICIES: Dict[str, Tuple[str, ...]] = {
    "shipped_confirmed": (CONFIRMED,),
    "triage_uncertain": (CONFIRMED, UNCERTAIN),
    "oracle_all_verdicts": (CONFIRMED, UNCERTAIN, REJECTED),
}


def _phase1_of(entry: dict) -> dict:
    if "phase1" in entry:
        return entry["phase1"] or {}
    return entry.get("report") or {}


def _phase2_of(entry: dict) -> Optional[dict]:
    phase2 = entry.get("phase2")
    return phase2 if isinstance(phase2, dict) and phase2 else None


def _predictions(entry: dict, sample_id: str,
                 statuses: Sequence[str]) -> List[Prediction]:
    phase2 = _phase2_of(entry)
    if phase2 is not None:
        return predictions_from_phase2(phase2, sample_id, statuses=statuses)
    return predictions_from_phase1(_phase1_of(entry), sample_id)


def _match_config(payload: dict, require_cwe: Optional[bool]) -> MatchConfig:
    provenance = (payload.get("metadata", {}) or {}).get("provenance", {}) or {}
    strict = (bool(provenance.get("require_cwe_match", True))
              if require_cwe is None else require_cwe)
    return MatchConfig(
        line_tolerance=int(provenance.get("line_tolerance", 5)),
        require_cwe_when_available=strict,
    )


def _dataset_path(payload: dict, override: Optional[str]) -> Path:
    if override:
        return Path(override)
    recorded = ((payload.get("metadata", {}) or {}).get("provenance", {}) or {}
                ).get("dataset")
    if not recorded:
        raise ValueError("no dataset in provenance; pass --dataset")
    path = Path(recorded)
    return path if path.is_absolute() else Path.cwd() / path


def score_policy(payload: dict, sample_id: str, statuses: Sequence[str],
                 dataset, cfg: MatchConfig) -> dict:
    reports = (payload.get("metadata", {}) or {}).get("reports") or []
    predictions: List[Prediction] = []
    for entry in reports:
        predictions.extend(
            _predictions(entry, entry.get("sample_id", sample_id),
                         statuses)
        )
    return evaluate(
        payload.get("experiment", "counterfactual"),
        predictions,
        list(dataset),
        match_config=cfg,
    )


def _has_phase1_findings(entry: dict) -> bool:
    return bool(_phase1_of(entry).get("findings"))


def decompose_misses(payload: dict, dataset, cfg: MatchConfig) -> Dict[str, Any]:
    """Attribute every missed positive to the stage that lost it.

    Order matters: a sample the matcher credited is not a miss, and a sample
    the candidate generator never proposed can only be blamed on Phase 1 --
    no downstream stage had a chance to see it.
    """
    reports = {entry.get("sample_id"): entry
               for entry in ((payload.get("metadata", {}) or {}).get("reports")
                             or [])}
    scored = score_policy(payload, "", (CONFIRMED,), dataset, cfg)
    detected = {match.prediction.sample_id for match in scored.matches}

    buckets = {
        "matched": 0,
        "candidate_ceiling": 0,
        "agent_silent": 0,
        "dropped_uncertain": 0,
        "dropped_rejected": 0,
        "confirmed_unmatched": 0,
        "no_report": 0,
    }
    per_cwe: Dict[str, Dict[str, int]] = {}

    for gt in dataset:
        if not gt.vulnerable:
            continue
        label = gt.cwe[0] if gt.cwe else "unlabelled"
        counts = per_cwe.setdefault(label, dict.fromkeys(buckets, 0))
        if gt.sample_id in detected:
            bucket = "matched"
        else:
            entry = reports.get(gt.sample_id)
            if entry is None:
                bucket = "no_report"
            elif not _phase2_of(entry):
                bucket = ("candidate_ceiling" if not _has_phase1_findings(entry)
                          else "agent_silent")
            else:
                verdicts = {str(d.get("status", UNCERTAIN)).upper()
                            for d in (_phase2_of(entry) or {}).get("decisions", [])
                            if isinstance(d, dict)}
                if not verdicts:
                    bucket = ("candidate_ceiling"
                              if not _has_phase1_findings(entry)
                              else "agent_silent")
                elif CONFIRMED in verdicts:
                    bucket = "confirmed_unmatched"
                elif UNCERTAIN in verdicts:
                    bucket = "dropped_uncertain"
                else:
                    bucket = "dropped_rejected"
        buckets[bucket] += 1
        counts[bucket] += 1

    positives = sum(1 for g in dataset if g.vulnerable)
    return {
        "positives": positives,
        "stages": buckets,
        "per_cwe": per_cwe,
        "recoverable_by_triage": buckets["dropped_uncertain"],
        "recoverable_ceiling": (
            buckets["dropped_uncertain"] + buckets["dropped_rejected"]
            + buckets["confirmed_unmatched"]
        ),
    }


def triage_queue(payload: dict) -> List[dict]:
    """UNCERTAIN verdicts ranked the way a human queue should be ranked."""
    entries: List[dict] = []
    for report in (payload.get("metadata", {}) or {}).get("reports") or []:
        phase2 = _phase2_of(report)
        if not phase2:
            continue
        sample_id = report.get("sample_id", "")
        for decision in phase2.get("decisions", []):
            if not isinstance(decision, dict):
                continue
            if str(decision.get("status", UNCERTAIN)).upper() != UNCERTAIN:
                continue
            entries.append({
                "sample_id": sample_id,
                "file": decision.get("file") or phase2.get("source", ""),
                "line": decision.get("line"),
                "cwe": decision.get("cwe") or [],
                "confidence": decision.get("confidence"),
                "rationale": decision.get("rationale", ""),
                "evidence": decision.get("evidence") or [],
            })
    entries.sort(
        key=lambda e: (-(e["confidence"] or 0.0), str(e["sample_id"]),
                       str(e["line"]))
    )
    for index, entry in enumerate(entries, start=1):
        entry["rank"] = index
    return entries


def _fmt_rate(metrics_dict: dict, name: str) -> str:
    value = metrics_dict.get(name, 0.0)
    interval = metrics_dict.get("ci95", {}).get(name)
    if not interval:
        return f"{value:.3f}"
    return f"{value:.3f} [{interval[0]:.3f}, {interval[1]:.3f}]"


def _delta(base: float, other: float) -> str:
    return f"{other - base:+.3f}"


def analyse(path: Path, dataset, require_cwe: Optional[bool]) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    reports = (payload.get("metadata", {}) or {}).get("reports")
    if not reports:
        return {"file": path.name,
                "skipped": "no metadata.reports to rebuild predictions from",
                "policies": {}, "miss_decomposition": None}

    cfg = _match_config(payload, require_cwe)
    phase2_present = any(_phase2_of(entry) for entry in reports)

    rows: Dict[str, dict] = {}
    if phase2_present:
        for name, statuses in POLICIES.items():
            result = score_policy(payload, "", statuses, dataset, cfg)
            rows[name] = {
                "statuses": list(statuses),
                "confusion": result.metrics.confusion.to_dict(),
                "precision": round(result.metrics.precision, 6),
                "recall": round(result.metrics.recall, 6),
                "f1": round(result.metrics.f1, 6),
                "false_positive_rate": round(
                    result.metrics.false_positive_rate, 6),
                "accuracy": round(result.metrics.accuracy, 6),
                "balanced_accuracy": round(
                    result.metrics.balanced_accuracy, 6),
                "ci95": result.metrics.ci95,
            }
    else:
        result = score_policy(payload, "", (CONFIRMED,), dataset, cfg)
        rows["phase1_unfiltered"] = {
            "statuses": ["phase1"],
            "confusion": result.metrics.confusion.to_dict(),
            "precision": round(result.metrics.precision, 6),
            "recall": round(result.metrics.recall, 6),
            "f1": round(result.metrics.f1, 6),
            "false_positive_rate": round(
                result.metrics.false_positive_rate, 6),
            "accuracy": round(result.metrics.accuracy, 6),
            "balanced_accuracy": round(result.metrics.balanced_accuracy, 6),
            "ci95": result.metrics.ci95,
        }

    decomposition = (decompose_misses(payload, dataset, cfg)
                     if phase2_present else None)
    return {
        "file": path.name,
        "match_config": {
            "line_tolerance": cfg.line_tolerance,
            "require_cwe_when_available": cfg.require_cwe_when_available,
        },
        "policies": rows,
        "miss_decomposition": decomposition,
        "triage_count": len(triage_queue(payload)) if phase2_present else 0,
    }


def _print_report(report: dict) -> None:
    print(f"\n=== {report['file']} ===")
    if "skipped" in report:
        print(f"  skipped: {report['skipped']}")
        return

    rows = report["policies"]
    baseline = next(iter(rows.values()))
    header = (f"  {'policy':<22}{'TP':>4}{'FP':>4}{'FN':>5}{'TN':>5}"
              f"{'P':>24}{'R':>24}{'FPR':>24}")
    print(header)
    for name, row in rows.items():
        c = row["confusion"]
        print(
            f"  {name:<22}{c['tp']:>4}{c['fp']:>4}{c['fn']:>5}{c['tn']:>5}"
            f"{_fmt_rate(row, 'precision'):>24}"
            f"{_fmt_rate(row, 'recall'):>24}"
            f"{_fmt_rate(row, 'false_positive_rate'):>24}"
        )
        if name != next(iter(rows)):
            print(
                f"  {'':<22}{'':>4}{'':>4}{'':>5}{'':>5}"
                f"{'dP ' + _delta(baseline['precision'], row['precision']):>24}"
                f"{'dR ' + _delta(baseline['recall'], row['recall']):>24}"
                f"{'dFPR ' + _delta(baseline['false_positive_rate'], row['false_positive_rate']):>24}"
            )

    decomposition = report.get("miss_decomposition")
    if decomposition:
        stages = decomposition["stages"]
        total = decomposition["positives"] or 1
        print(f"\n  miss decomposition ({decomposition['positives']} positives)")
        for stage, count in stages.items():
            if count:
                print(f"    {stage:<24}{count:>5}  ({count / total:6.1%})")
        print(f"    recoverable by triage (UNCERTAIN): "
              f"{decomposition['recoverable_by_triage']}")
        print(f"    ceiling incl. REJECTED/unmatched: "
              f"{decomposition['recoverable_ceiling']}")
        for label, counts in decomposition["per_cwe"].items():
            nonzero = {k: v for k, v in counts.items()
                       if v and k not in ("matched",)}
            if nonzero:
                print(f"    {label}: {nonzero}")
    if report.get("triage_count"):
        print(f"  triage queue: {report['triage_count']} UNCERTAIN verdicts")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("results", nargs="+", help="Phase-3 result JSON files")
    parser.add_argument("--dataset",
                        help="override the dataset in each provenance block")
    parser.add_argument("--no-cwe-match",
                        action="store_true",
                        help="score file + line only instead of the run's own "
                             "matching policy")
    parser.add_argument("--json",
                        help="write the full report (tables + decomposition) "
                             "to this file")
    parser.add_argument("--triage-dir",
                        help="write one ranked UNCERTAIN queue per result to "
                             "<DIR>/<result stem>.triage.json")
    args = parser.parse_args()

    reports: List[dict] = []
    triage_dir = Path(args.triage_dir) if args.triage_dir else None
    for name in args.results:
        path = Path(name)
        payload = json.loads(path.read_text(encoding="utf-8"))
        dataset_path = _dataset_path(payload, args.dataset)
        dataset = GroundTruthDataset.from_json(str(dataset_path))
        report = analyse(path, dataset,
                         require_cwe=False if args.no_cwe_match else None)
        reports.append(report)
        _print_report(report)

        if triage_dir is not None:
            queue = triage_queue(payload)
            triage_dir.mkdir(parents=True, exist_ok=True)
            target = triage_dir / f"{path.stem}.triage.json"
            target.write_text(
                json.dumps(queue, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            print(f"  wrote {len(queue)} triage entries to {target}")

    if args.json:
        target = Path(args.json)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps({"reports": reports}, indent=2, ensure_ascii=False)
            + "\n",
            encoding="utf-8",
        )
        print(f"\nwrote {target}")


if __name__ == "__main__":
    main()
