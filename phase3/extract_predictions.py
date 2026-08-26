from __future__ import annotations
from typing import Any, Dict, List
from .models import Prediction

def predictions_from_phase1(report: Dict[str, Any], sample_id: str) -> List[Prediction]:
    source=str(report.get("source") or report.get("path") or "")
    return [Prediction(sample_id=sample_id,file=str(f.get("file") or source),vulnerable=True,cwe=[str(x) for x in f.get("cwe",[])],line=int(f["line"]) if f.get("line") is not None else None,status="CONFIRMED",confidence=float(f.get("confidence") or 0.0),source=str(f.get("tool") or "phase1"),fingerprint=f.get("fingerprint"),raw=f) for f in report.get("findings",[])]

def predictions_from_phase2(report: Dict[str, Any], sample_id: str) -> List[Prediction]:
    source=str(report.get("source") or report.get("path") or "")
    out=[]
    for d in report.get("decisions",[]):
        if str(d.get("status","UNCERTAIN")).upper() != "CONFIRMED": continue
        out.append(Prediction(sample_id=sample_id,file=str(d.get("file") or source),vulnerable=True,cwe=[str(x) for x in d.get("cwe",[])],line=int(d["line"]) if d.get("line") is not None else None,status="CONFIRMED",confidence=float(d.get("confidence") or 0.0),source="phase2",raw=d))
    return out
