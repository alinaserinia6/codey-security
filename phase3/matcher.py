from __future__ import annotations
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import List, Optional, Sequence, Tuple

from .models import GroundTruth, Match, Prediction


@dataclass(frozen=True)
class MatchConfig:
    line_tolerance: int = 5
    require_cwe_when_available: bool = True


def _norm(path: str) -> str:
    return path.replace("\\", "/").rstrip("/")


def _same_file(a: str, b: str) -> bool:
    """Return True when two paths refer to the same source file.

    Uses component-aware suffix matching so that, e.g., ``foo.c`` never
    matches ``verylongfoo.c``. The earlier implementation used a bare
    ``str.endswith`` which produced false positives on Juliet-style
    filenames such as ``*_01.c``.
    """
    if not a or not b:
        return False
    a, b = _norm(a), _norm(b)
    if a == b:
        return True

    pa, pb = PurePosixPath(a), PurePosixPath(b)
    if pa.name != pb.name:
        return False

    a_parts, b_parts = pa.parts, pb.parts
    if len(a_parts) >= len(b_parts):
        return list(a_parts[-len(b_parts):]) == list(b_parts)
    return list(b_parts[-len(a_parts):]) == list(a_parts)


def match_score(pred: Prediction, gt: GroundTruth, cfg: MatchConfig) -> Tuple[float, str]:
    if not _same_file(pred.file, gt.file):
        return 0.0, "file mismatch"

    reasons = ["file match"]
    score = 0.4

    if cfg.require_cwe_when_available and gt.cwe and pred.cwe and not (set(pred.cwe) & set(gt.cwe)):
        return 0.0, "CWE mismatch"
    if gt.cwe and pred.cwe and (set(pred.cwe) & set(gt.cwe)):
        score += 0.25
        reasons.append("CWE overlap")

    if gt.line is not None and pred.line is not None:
        delta = abs(gt.line - pred.line)
        if delta > cfg.line_tolerance:
            return 0.0, "line mismatch"
        score += 0.35 * (1 - delta / max(cfg.line_tolerance, 1))
        reasons.append(f"line within {cfg.line_tolerance}")
    else:
        score += 0.10

    return min(score, 1.0), "; ".join(reasons)


def greedy_match(
    predictions: Sequence[Prediction],
    ground_truth: Sequence[GroundTruth],
    cfg: Optional[MatchConfig] = None,
):
    cfg = cfg or MatchConfig()
    candidates = []
    for pi, p in enumerate(predictions):
        for gi, g in enumerate(ground_truth):
            score, reason = match_score(p, g, cfg)
            if score > 0:
                candidates.append((score, pi, gi, reason))

    candidates.sort(reverse=True)
    used_p = set()
    used_g = set()
    matches: List[Match] = []
    for score, pi, gi, reason in candidates:
        if pi in used_p or gi in used_g:
            continue
        used_p.add(pi)
        used_g.add(gi)
        matches.append(Match(predictions[pi], ground_truth[gi], score, reason))

    return (
        matches,
        [p for i, p in enumerate(predictions) if i not in used_p],
        [g for i, g in enumerate(ground_truth) if i not in used_g],
    )
