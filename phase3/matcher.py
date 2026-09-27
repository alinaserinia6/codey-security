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
# Keys are child CWEs; values are the set of CWEs treated as equivalent for
# matching purposes. The map is symmetric in effect because _cwe_family
# unions both directions when a sample and a prediction are compared.
_CWE_PARENTS: dict[str, Set[str]] = {
    # --- Buffer / memory-safety family (CWE-119 is the umbrella) ----------
    "CWE-119": {"CWE-118"},
    "CWE-120": {"CWE-119", "CWE-118"},
    "CWE-121": {"CWE-119", "CWE-118"},
    "CWE-122": {"CWE-119", "CWE-118"},
    "CWE-123": {"CWE-119", "CWE-118"},
    "CWE-124": {"CWE-119", "CWE-118"},
    "CWE-125": {"CWE-119", "CWE-118"},
    "CWE-126": {"CWE-119", "CWE-118"},
    "CWE-127": {"CWE-119", "CWE-118"},
    "CWE-131": {"CWE-119", "CWE-118"},
    "CWE-787": {"CWE-119", "CWE-118"},
    "CWE-788": {"CWE-119", "CWE-118"},
    # --- Integer family --------------------------------------------------
    "CWE-189": {"CWE-682"},
    "CWE-190": {"CWE-189", "CWE-682"},
    "CWE-191": {"CWE-189", "CWE-682"},
    "CWE-192": {"CWE-189", "CWE-682"},
    "CWE-194": {"CWE-189", "CWE-682"},
    "CWE-195": {"CWE-189", "CWE-682"},
    "CWE-196": {"CWE-189", "CWE-682"},
    "CWE-197": {"CWE-189", "CWE-682"},
    # --- Command / code injection ---------------------------------------
    "CWE-78": {"CWE-77", "CWE-74"},
    "CWE-77": {"CWE-74"},
    "CWE-94": {"CWE-74"},
    # --- Format string ---------------------------------------------------
    "CWE-134": {"CWE-668"},
    # --- Use-after-free / double-free family -----------------------------
    "CWE-415": {"CWE-416", "CWE-664", "CWE-404"},
    "CWE-416": {"CWE-415", "CWE-664", "CWE-404"},
    # --- NULL pointer dereference ---------------------------------------
    "CWE-476": {"CWE-710"},
    # --- Path traversal --------------------------------------------------
    "CWE-22": {"CWE-23", "CWE-36", "CWE-59", "CWE-706"},
    "CWE-23": {"CWE-22", "CWE-706"},
    "CWE-36": {"CWE-22", "CWE-706"},
    # --- Information exposure -------------------------------------------
    "CWE-200": {"CWE-538", "CWE-668"},
    "CWE-532": {"CWE-200", "CWE-538"},
    "CWE-534": {"CWE-200", "CWE-538"},
    # --- Improper access control ----------------------------------------
    "CWE-284": {"CWE-285", "CWE-862", "CWE-863"},
    "CWE-285": {"CWE-284"},
    # --- Resource management --------------------------------------------
    "CWE-400": {"CWE-664"},
    "CWE-401": {"CWE-404", "CWE-664", "CWE-772"},
    "CWE-404": {"CWE-664"},
    "CWE-772": {"CWE-404", "CWE-664"},
    # --- Cryptographic issues -------------------------------------------
    "CWE-327": {"CWE-693", "CWE-311"},
    "CWE-328": {"CWE-327", "CWE-693"},
    "CWE-338": {"CWE-330", "CWE-693"},
}


def _cwe_family(cwe: str) -> Set[str]:
    """Return the CWE plus all known relatives (up to two hops)."""
    root = cwe.upper().strip()
    family: Set[str] = {root}
    for parent in _CWE_PARENTS.get(root, set()):
        parent = parent.upper()
        family.add(parent)
        for grandparent in _CWE_PARENTS.get(parent, set()):
            family.add(grandparent.upper())
    return family


def _cwes_match(pred_cwe: Sequence[str], gt_cwe: Sequence[str]) -> bool:
    """True if any prediction CWE shares a family with any ground-truth CWE."""
    if not pred_cwe or not gt_cwe:
        return False
    pred_family: Set[str] = set()
    for c in pred_cwe:
        pred_family |= _cwe_family(c)
    gt_family: Set[str] = set()
    for c in gt_cwe:
        gt_family |= _cwe_family(c)
    return bool(pred_family & gt_family)


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
    # When the ground truth names a CWE, the prediction must share its family.
    # A CWE-less prediction cannot be credited as a match: otherwise every
    # style/quality warning in the same file would count as a true positive.
    if gt.cwe:
        if not pred.cwe:
            return 0.0, "prediction has no CWE; cannot match CWE-bearing ground truth"
        if not _cwes_match(pred.cwe, gt.cwe):
            return 0.0, "CWE mismatch (no shared family)"
        score += 0.25
        reasons.append("CWE overlap")

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
