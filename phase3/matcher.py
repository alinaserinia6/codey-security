from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import List, Optional, Sequence, Set, Tuple

from .models import GroundTruth, Match, Prediction


@dataclass(frozen=True)
class MatchConfig:
    line_tolerance: int = 5
    require_cwe_when_available: bool = True


# ---------------------------------------------------------------------------
# CWE family relationships
# ---------------------------------------------------------------------------
# Static tools frequently report a *parent* CWE where Juliet's ground truth
# names a specific child. For example, Flawfinder reports "CWE-119" for any
# buffer operation, while the Juliet sample CWE122_Heap_Based_Buffer_Overflow
# declares "CWE-122". Without this map those detections are counted as false
# positives and the same sample also appears as a false negative.
#
# The map itself lives in ``analyzers.cwe_family`` so that Phase 2 can group
# duplicate claims with the same notion of "equivalent CWE" this matcher scores
# with, without depending on the evaluation layer.
from analyzers.cwe_family import cwes_match as _cwes_match  # noqa: E402


# ---------------------------------------------------------------------------
# File matching
# ---------------------------------------------------------------------------
def _norm(path: str) -> str:
    return path.replace("\\", "/").rstrip("/")


def _same_file(a: str, b: str) -> bool:
    """Return True when two paths refer to the same source file.

    Uses component-aware suffix matching so that, e.g., ``foo.c`` never
    matches ``verylongfoo.c``. A bare ``str.endswith`` would produce false
    positives on Juliet-style filenames such as ``*_01.c``.
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


# ---------------------------------------------------------------------------
# Match scoring
# ---------------------------------------------------------------------------
def match_score(pred: Prediction, gt: GroundTruth, cfg: MatchConfig) -> Tuple[float, str]:
    if not _same_file(pred.file, gt.file):
        return 0.0, "file mismatch"

    reasons = ["file match"]
    score = 0.4

    # --- CWE policy -----------------------------------------------------
    # When the ground truth names a CWE, the prediction must share its
    # family. A CWE-less prediction cannot be credited as a match: otherwise
    # every style/quality warning in the same file would count as a true
    # positive. That absence check is unconditional.
    #
    # The *agreement* half is optional: `require_cwe_when_available=False`
    # (the `--no-cwe-match` flag, `SCENARIO_PHASE3_REQUIRE_CWE=false`) means
    # file + line alone decide. The field used to be read from config and
    # echoed into the report, but never reached this function, so the flag
    # silently did nothing.
    if gt.cwe:
        if not pred.cwe:
            return 0.0, "prediction has no CWE; cannot match CWE-bearing ground truth"
        if cfg.require_cwe_when_available:
            if not _cwes_match(pred.cwe, gt.cwe):
                return 0.0, "CWE mismatch (no shared family)"
            score += 0.25
            reasons.append("CWE overlap")
        else:
            reasons.append("CWE check disabled")

    # --- Line policy ----------------------------------------------------
    if gt.line is not None and pred.line is not None:
        delta = abs(gt.line - pred.line)
        if delta > cfg.line_tolerance:
            return 0.0, "line mismatch"
        score += 0.35 * (1 - delta / max(cfg.line_tolerance, 1))
        reasons.append(f"line within {cfg.line_tolerance}")
    else:
        # No line on one side (common for HF-extracted Juliet samples):
        # fall back to a small bonus so file+CWE still scores well.
        score += 0.10

    return min(score, 1.0), "; ".join(reasons)


# ---------------------------------------------------------------------------
# Greedy matching
# ---------------------------------------------------------------------------
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
    used_p: Set[int] = set()
    used_g: Set[int] = set()
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
