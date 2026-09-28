from pathlib import Path

from analyzers.finding import Finding
from codey_security import (
    _analyze_file_report,
    _merge_phase2_reports,
    _pipeline_method,
)
from phase3.metrics import compute_metrics
from phase3.models import ConfusionMatrix


def test_core_models_import():
    f = Finding(tool="test", rule_id="R1", message="x")
    assert f.tool == "test"
    metrics = compute_metrics(ConfusionMatrix(tp=2, fp=1, fn=1, tn=6))
    assert round(metrics.precision, 6) == round(2 / 3, 6)
    assert round(metrics.recall, 6) == round(2 / 3, 6)


def test_pipeline_method_matches_selected_architecture():
    assert _pipeline_method("multi_agent") == "scanner_then_verifier"
    assert _pipeline_method("single_agent") == "single_security_agent"


def test_directory_merge_preserves_method_and_pipeline_failures():
    class Phase1:
        def analyze_file(self, path):
            return {"language": "python"}

    class Phase2:
        async def analyze_report(self, report):
            return {
                "source": "a.py",
                "language": "python",
                "decisions": [{"status": "CONFIRMED"}],
                "errors": [],
                "metadata": {"input_group_count": 1},
            }

    class BrokenPhase2:
        async def analyze_report(self, report):
            raise RuntimeError("boom")

    good = _analyze_file_report(Phase1(), Phase2(), Path("a.py"))
    bad = _analyze_file_report(Phase1(), BrokenPhase2(), Path("b.py"))
    merged = _merge_phase2_reports(
        "root", [good, bad], method=_pipeline_method("multi_agent")
    )

    assert merged["metadata"]["method"] == "scanner_then_verifier"
    assert merged["metadata"]["decision_counts"] == {
        "CONFIRMED": 1,
        "REJECTED": 0,
        "UNCERTAIN": 0,
    }
    assert merged["errors"] == ["b.py: RuntimeError: boom"]
