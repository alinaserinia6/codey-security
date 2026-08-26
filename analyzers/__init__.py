"""Phase 1 analysis components.

Imports are intentionally lightweight so evaluation-only workflows do not
require Tree-sitter at import time.
"""
from .finding import Finding, NormalizedReport

__all__ = ["Finding", "NormalizedReport", "StructuralAnalyzer", "Phase1Pipeline"]


def __getattr__(name):
    if name == "StructuralAnalyzer":
        from .structural_analyzer import StructuralAnalyzer
        return StructuralAnalyzer
    if name == "Phase1Pipeline":
        from .phase1_pipeline import Phase1Pipeline
        return Phase1Pipeline
    raise AttributeError(name)
