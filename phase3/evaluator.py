from __future__ import annotations
from typing import Iterable
from .matcher import MatchConfig, greedy_match
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
    fp=len(unmatched_positive_predictions)+len(benign_pred_ids)
    fn=len(unmatched_gts)
    tn=len(benign_ids-benign_pred_ids)
    metrics=compute_metrics(ConfusionMatrix(len(matches),fp,fn,tn),matched_predictions=len(matches),unmatched_predictions=fp)
    per_cwe=_per_cwe(pos_preds,pos_gts,cfg)
    return EvaluationResult(experiment,metrics,matches,unmatched_preds,unmatched_gts,per_cwe,{
        "prediction_count":len(preds),"positive_prediction_count":len(pos_preds),"ground_truth_count":len(gts),
        "positive_ground_truth_count":len(pos_gts),"negative_ground_truth_count":len(neg_gts),
        "matching":{"line_tolerance":cfg.line_tolerance,"require_cwe_when_available":cfg.require_cwe_when_available},
        "metric_granularity":"TP/FP/FN are finding-level; TN/negative support are sample-level.",
    })

def _per_cwe(preds: list[Prediction], gts: list[GroundTruth], cfg: MatchConfig) -> dict[str,Metrics]:
    cwes=sorted({c for g in gts for c in g.cwe}|{c for p in preds for c in p.cwe}); out={}
    for cwe in cwes:
        pg=[g for g in gts if g.vulnerable and cwe in g.cwe]
        benign=[g for g in gts if not g.vulnerable and cwe in g.cwe]
        pp=[p for p in preds if cwe in p.cwe and p.vulnerable]
        m,up,ug=greedy_match(pp,pg,cfg)
        predicted_benign={p.sample_id for p in pp if any(g.sample_id == p.sample_id for g in benign)}
        fp=len(up)+len(predicted_benign)
        tn=len({g.sample_id for g in benign} - predicted_benign)
        out[cwe]=compute_metrics(ConfusionMatrix(len(m),fp,len(ug),tn),matched_predictions=len(m),unmatched_predictions=fp)
    return out
