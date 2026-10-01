"""CWE family relationships shared by the matcher and the Phase 2 pipeline.

Static tools frequently report a *parent* CWE where the ground truth names a
specific child: Flawfinder reports "CWE-119" for any buffer operation while the
sample declares "CWE-122". The evaluator folds those together when it scores a
prediction, so anything that has to decide *what counts as the same claim* —
the matcher, and the Phase 2 report that groups duplicate findings — must fold
them the same way. Keeping one map here is what stops the two from drifting.

The map lives in ``analyzers`` rather than in ``phase3`` because Phase 2 (the
pipeline that produces findings) must not depend on Phase 3 (the layer that
scores them).
"""
from __future__ import annotations

from typing import Iterable, Sequence, Set

# Keys are child CWEs; values are the set of CWEs treated as equivalent for
# matching purposes. The map is symmetric in effect because `cwe_family`
# unions both directions when a sample and a prediction are compared.
CWE_PARENTS: dict[str, Set[str]] = {
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


def cwe_family(cwe: str) -> Set[str]:
    """Return the CWE plus all known relatives (up to two hops)."""
    root = str(cwe or "").upper().strip()
    family: Set[str] = {root}
    for parent in CWE_PARENTS.get(root, set()):
        parent = parent.upper()
        family.add(parent)
        for grandparent in CWE_PARENTS.get(parent, set()):
            family.add(grandparent.upper())
    return family


def families_of(cwes: Iterable[str]) -> Set[str]:
    """The union of :func:`cwe_family` over a CWE list."""
    family: Set[str] = set()
    for cwe in cwes or []:
        family |= cwe_family(cwe)
    return family


def cwes_match(pred_cwe: Sequence[str], gt_cwe: Sequence[str]) -> bool:
    """True if any prediction CWE shares a family with any ground-truth CWE."""
    if not pred_cwe or not gt_cwe:
        return False
    return bool(families_of(pred_cwe) & families_of(gt_cwe))
