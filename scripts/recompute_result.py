"""Recompute metrics of existing Phase-3 results without re-running anything.

Reporting bugs live in the evaluation layer, not in the analyzers or the LLM
calls, so re-running a full benchmark is a needlessly expensive way to fix
them.  Every Phase-3 result file keeps the per-sample Phase-1/Phase-2 reports
under ``metadata.reports``, which is exactly the input ``evaluate()`` needs.

The script rebuilds the predictions from those stored reports, re-evaluates
them against the dataset named in the provenance block, and writes the
refreshed result back.  Provenance is preserved and annotated so a reader can
tell that the numbers were recomputed rather than freshly measured.

A run scored straight from the model's verdicts (the LLM-only leg) writes no
reports, so there is nothing to rebuild from.  For those files the script falls
back to the finding set already stored in the result -- every prediction is
either in ``matches`` or in ``unmatched_predictions`` -- and re-scores that.
No model call is made either way.

Usage:
    python scripts/recompute_result.py results/exp_C_static_llm_subset600.json
    python scripts/recompute_result.py --dataset datasets/vulnllm_r_c.json results/*.json

Two matching protocols are reported. ``SCENARIO_PHASE3_REQUIRE_CWE=true``
(strict, the default a run is made with) demands that a finding's CWE match
the ground-truth CWE; it is the corpus's own CWE-strict convention. The
CWE-agnostic variant scores file + line only and shows how much of a result is
lost to vocabulary mismatch between the tools and the labels. Both are derived
from the same stored reports, so the second table costs no model calls:

    python scripts/recompute_result.py --no-cwe-match --out results/agnostic \
        results/exp_vulnllm_r_c_static.json
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from phase3.dataset import GroundTruthDataset  # noqa: E402
from phase3.evaluator import evaluate  # noqa: E402
from phase3.extract_predictions import (  # noqa: E402
    predictions_from_phase1,
    predictions_from_phase2,
)
from phase3.matcher import MatchConfig  # noqa: E402
from phase3.models import Prediction  # noqa: E402


def _phase1_of(entry: dict) -> dict:
    """Phase-1 mode stores the analyzer output under ``report``; phase-2 mode
    nests it under ``phase1``.  Both are accepted here."""
    if "phase1" in entry:
        return entry["phase1"] or {}
    return entry.get("report") or {}


def _rebuild_predictions(entry: dict, sample_id: str) -> list:
    """Rebuild the prediction list a run would have produced for one sample.

    Phase-2 mode reports *only* confirmed findings, so when a Phase-2 block is
    present it is the authoritative source; otherwise the raw Phase-1 findings
    are the predictions.
    """
    phase2 = entry.get("phase2")
    if isinstance(phase2, dict) and phase2:
        return predictions_from_phase2(phase2, sample_id)
    return predictions_from_phase1(_phase1_of(entry), sample_id)


def _unmatched_to_prediction(entry: dict) -> Prediction:
    """Read one stored unmatched finding back as a ``Prediction``.

    ``EvaluationResult.to_dict`` annotates unmatched findings on the way out:
    the run's assertion is renamed ``vulnerable`` -> ``claims_vulnerable`` and
    the sample's own label is written next to it.  Both generations of that
    shape are accepted here so a file written before the rename can still be
    re-scored.
    """
    data = dict(entry)
    if "vulnerable" not in data:
        if "claims_vulnerable" not in data:
            raise ValueError(
                "stored unmatched prediction carries neither 'vulnerable' nor "
                f"'claims_vulnerable'; keys were {sorted(data)}"
            )
        data["vulnerable"] = data.pop("claims_vulnerable")
        data.pop("sample_vulnerable", None)
        data.pop("failure", None)
    return Prediction(**data)


def _order_key(pred: Prediction) -> tuple:
    """Canonical order for a rebuilt prediction set.

    ``greedy_match`` breaks score ties by prediction index, so the order the
    predictions are handed to it leaks into the order of the ``matches`` list
    it returns -- rebuilding them from ``matches`` + ``unmatched_predictions``
    would otherwise shuffle that list on every pass.  Sorting fixes the order
    so re-scoring the same file twice writes the same bytes.  The score set,
    and therefore every metric, is unaffected.
    """
    return (
        pred.sample_id,
        pred.line if pred.line is not None else -1,
        ",".join(sorted(pred.cwe)),
        pred.source,
        pred.finding_id or "",
    )


def _predictions_from_result(payload: dict) -> list:
    """Rebuild the prediction list of a run that stores no reports.

    The LLM-only leg is scored straight from the model's verdicts, so no
    per-sample Phase-1/Phase-2 block is written and ``metadata.reports`` is
    absent.  Every prediction such a run produced is already in the file
    itself -- it is either credited in ``matches`` or left in
    ``unmatched_predictions`` -- so the finding set can be read back and
    re-scored without re-running a single model call.

    The two lists partition the predictions, so their lengths are checked
    against ``metadata.positive_prediction_count``: re-scoring a partial set
    would produce a plausible-looking but wrong table.
    """
    preds: list[Prediction] = []
    for match in payload.get("matches") or []:
        preds.append(Prediction(**match["prediction"]))
    for entry in payload.get("unmatched_predictions") or []:
        preds.append(_unmatched_to_prediction(entry))
    preds.sort(key=_order_key)

    expected = ((payload.get("metadata", {}) or {})
                .get("positive_prediction_count"))
    if expected is not None:
        found = len([p for p in preds if p.vulnerable])
        if found != expected:
            raise ValueError(
                f"rebuilt {found} predictions but the result records "
                f"{expected}; the stored finding set is incomplete"
            )
    return preds


def recompute(path: Path, dataset_path: Path | None,
              require_cwe: bool | None = None) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    provenance = (payload.get("metadata", {}) or {}).get("provenance", {}) or {}

    if dataset_path is not None:
        ds_path = Path(dataset_path)
    else:
        recorded = provenance.get("dataset")
        if not recorded:
            raise ValueError(f"{path}: no dataset in provenance; pass --dataset")
        ds_path = Path(recorded)
    if not ds_path.is_absolute():
        ds_path = Path.cwd() / ds_path

    dataset = GroundTruthDataset.from_json(str(ds_path))
    reports = (payload.get("metadata", {}) or {}).get("reports", [])
    predictions: list = []
    if reports:
        for entry in reports:
            predictions.extend(
                _rebuild_predictions(entry, entry.get("sample_id", ""))  # type: ignore[arg-type]
            )
        rebuilt_from = "metadata.reports"
    else:
        predictions = _predictions_from_result(payload)
        if not predictions:
            raise ValueError(
                f"{path}: no metadata.reports and no stored findings to "
                "recompute from"
            )
        rebuilt_from = "metadata.matches + metadata.unmatched_predictions"

    strict = (bool(provenance.get("require_cwe_match", True))
              if require_cwe is None else require_cwe)
    cfg = MatchConfig(
        line_tolerance=int(provenance.get("line_tolerance", 5)),
        require_cwe_when_available=strict,
    )
    result = evaluate(
        payload.get("experiment", path.stem),
        predictions,
        list(dataset),
        match_config=cfg,
    )

    refreshed = result.to_dict()
    if reports:
        refreshed["metadata"]["reports"] = reports
    prov = dict((payload.get("metadata", {}) or {}).get("provenance", {}) or {})
    prov["metrics_recomputed_at"] = datetime.now(timezone.utc).isoformat(
        timespec="seconds"
    )
    prov["metrics_recomputed_from"] = rebuilt_from
    prov["dataset"] = str(ds_path)
    # Make the variant legible in the file itself: a strict table and an
    # agnostic table must never be mistaken for each other downstream.
    prov["matching_variant"] = (
        "cwe_agnostic" if not strict else
        prov.get("matching_variant", "cwe_strict")
    )
    refreshed["metadata"]["provenance"] = prov
    # keep the human-readable run label if the original run had one
    label = (payload.get("metadata", {}) or {}).get("provenance", {}).get("label")
    if label:
        refreshed["metadata"]["provenance"]["label"] = label
    return refreshed


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("results", nargs="+", help="Phase-3 result JSON files")
    ap.add_argument(
        "--dataset",
        help="override the dataset recorded in each result's provenance",
    )
    ap.add_argument(
        "--no-cwe-match",
        action="store_true",
        help="score file + line only (CWE-agnostic secondary table) instead "
             "of the run's own matching policy",
    )
    ap.add_argument(
        "--out",
        help="write refreshed results to this directory (default: in place)",
    )
    args = ap.parse_args()

    for name in args.results:
        src = Path(name)
        refreshed = recompute(
            src,
            Path(args.dataset) if args.dataset else None,
            require_cwe=False if args.no_cwe_match else None,
        )
        dest = src if not args.out else Path(args.out) / src.name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(
            json.dumps(refreshed, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        m = refreshed["metrics"]
        sl = refreshed["metadata"]["sample_level"]
        variant = refreshed["metadata"]["provenance"].get(
            "matching_variant", "cwe_strict"
        )
        print(
            f"{dest.name} [{variant}]: "
            f"tp={m['confusion']['tp']} fp={m['confusion']['fp']} "
            f"P={m['precision']:.4f} R={m['recall']:.4f} F1={m['f1']:.4f} "
            f"benign_flag={sl['benign_flag_rate']:.4f}"
        )


if __name__ == "__main__":
    main()
