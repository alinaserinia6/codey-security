from __future__ import annotations
from typing import Iterable
from .matcher import MatchConfig, greedy_match, _cwes_match
from .metrics import compute_metrics
from .models import ConfusionMatrix, EvaluationResult, GroundTruth, Metrics, Prediction

def evaluate(experiment: str, predictions: Iterable[Prediction], ground_truth: Iterable[GroundTruth], *, match_config: MatchConfig | None = None) -> EvaluationResult:
    cfg=match_config or MatchConfig(); preds=list(predictions); gts=list(ground_truth)
    pos_gts=[g for g in gts if g.vulnerable]; neg_gts=[g for g in gts if not g.vulnerable]
    pos_preds=[p for p in preds if p.vulnerable]
    matches, unmatched_preds, unmatched_gts=greedy_match(pos_preds,pos_gts,cfg)
    benign_ids={g.sample_id for g in neg_gts}
    benign_pred_ids={p.sample_id for p in pos_preds if p.sample_id in benign_ids}
    unmatched_positive_predictions=[p for p in unmatched_preds if p.sample_id not in benign_ids]
    # FP is finding-level (see README), so a benign file carrying three
    # findings contributes three false positives, not one: the sample-level
    # view of the same file lives in benign_pred_ids/tn below.
    benign_findings=[p for p in pos_preds if p.sample_id in benign_ids]
    fp=len(unmatched_positive_predictions)+len(benign_findings)
    fn=len(unmatched_gts)
    tn=len(benign_ids-benign_pred_ids)
    metrics=compute_metrics(ConfusionMatrix(len(matches),fp,fn,tn),matched_predictions=len(matches),unmatched_predictions=fp)
    per_cwe=_per_cwe(pos_preds,gts,cfg)
    return EvaluationResult(experiment,metrics,matches,unmatched_preds,unmatched_gts,per_cwe,{
        "prediction_count":len(preds),"positive_prediction_count":len(pos_preds),"ground_truth_count":len(gts),
        "positive_ground_truth_count":len(pos_gts),"negative_ground_truth_count":len(neg_gts),
        "matching":{"line_tolerance":cfg.line_tolerance,"require_cwe_when_available":cfg.require_cwe_when_available},
        "metric_granularity":"TP/FP/FN are finding-level; TN/negative support are sample-level.",
        "sample_level":_sample_level(pos_preds,pos_gts,neg_gts,benign_ids,benign_pred_ids,matches,unmatched_positive_predictions),
    })

def _sample_level(pos_preds, pos_gts, neg_gts, benign_ids, benign_pred_ids, matches, unmatched_positive_predictions) -> dict:
    """Per-file view of the same evaluation.

    ``metrics.false_positive_rate`` mixes two populations: findings raised on
    benign files and findings on vulnerable files that failed to match.  A
    false-positive rate is only meaningful against the benign population, so
    this block reports the two separately and is the number to quote when the
    claim is about false positives.
    """
    benign_flagged=len(benign_pred_ids)
    benign_total=len(neg_gts)
    matched_sample_ids={m.prediction.sample_id for m in matches}
    # Findings raised on a *benign* file belong to the benign population;
    # including them here would inflate the per-vulnerable-file average with
    # the very noise benign_flag_rate is meant to describe.
    vulnerable_ids={g.sample_id for g in pos_gts}
    findings_on_vulnerable=[p for p in pos_preds if p.sample_id in vulnerable_ids]
    return {
        "vulnerable_samples":len(pos_gts),
        "vulnerable_detected":len(matched_sample_ids),
        "vulnerable_detection_rate":(len(matched_sample_ids)/len(pos_gts)) if pos_gts else 0.0,
        "benign_samples":benign_total,
        "benign_flagged":benign_flagged,
        "benign_flag_rate":(benign_flagged/benign_total) if benign_total else 0.0,
        "unmatched_findings_on_vulnerable":len(unmatched_positive_predictions),
        "findings_per_vulnerable_file":(len(findings_on_vulnerable)/len(pos_gts)) if pos_gts else 0.0,
    }

def _per_cwe(preds: list[Prediction], gts: list[GroundTruth], cfg: MatchConfig) -> dict[str,Metrics]:
    """Per-CWE breakdown using the same policy as the aggregate metrics.

    Three properties are inherited from :func:`evaluate` on purpose:

    * the benign population of a CWE is the set of *benign* samples labelled
      with that CWE, so ``TN`` is meaningful (Juliet labels its ``good``
      variants with the CWE of the paired scenario);
    * a prediction is attributed to a CWE through the CWE *family* map, the
      same way the aggregate matcher credits a parent CWE such as CWE-120 to
      a child CWE such as CWE-122;
    * predictions are restricted to the files of that CWE's population, so
      warnings raised in unrelated files are not counted against it.
    """
    cwes=sorted({c for g in gts for c in g.cwe})
    out={}
    for cwe in cwes:
        pg=[g for g in gts if g.vulnerable and cwe in g.cwe]
        benign={g.sample_id for g in gts if not g.vulnerable and cwe in g.cwe}
        population={g.sample_id for g in pg}|benign
        pp=[p for p in preds
            if p.vulnerable and p.sample_id in population and _cwes_match([cwe],p.cwe)]
        m,up,ug=greedy_match(pp,pg,cfg)
        predicted_benign={p.sample_id for p in pp if p.sample_id in benign}
        # A prediction on a benign file is a false positive on that file, not a
        # failed match; counting it in both terms would double count it.  FP is
        # finding-level, so the benign side is tallied per finding while tn
        # stays sample-level and counts flagged samples.
        benign_unmatched=[p for p in up if p.sample_id in benign]
        fp=len([p for p in up if p.sample_id not in benign])+len(benign_unmatched)
        tn=len(benign-predicted_benign)
        out[cwe]=compute_metrics(ConfusionMatrix(len(m),fp,len(ug),tn),matched_predictions=len(m),unmatched_predictions=fp)
    return out
