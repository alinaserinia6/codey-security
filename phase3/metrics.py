from __future__ import annotations
from math import isfinite
from .models import ConfusionMatrix, Metrics

def _div(a,b):
    if not b: return 0.0
    v=a/b; return v if isfinite(v) else 0.0

def compute_metrics(cm: ConfusionMatrix, *, matched_predictions=0, unmatched_predictions=0) -> Metrics:
    tp,fp,fn,tn=cm.tp,cm.fp,cm.fn,cm.tn
    precision=_div(tp,tp+fp); recall=_div(tp,tp+fn); f1=_div(2*precision*recall,precision+recall)
    specificity=_div(tn,tn+fp); fpr=_div(fp,fp+tn); fnr=_div(fn,fn+tp); accuracy=_div(tp+tn,tp+tn+fp+fn)
    balanced=(recall+specificity)/2 if (tp+fn)>0 and (tn+fp)>0 else 0.0
    return Metrics(cm,precision,recall,f1,fpr,specificity,fnr,accuracy,balanced,tp+fn,tn+fp,matched_predictions,unmatched_predictions)
