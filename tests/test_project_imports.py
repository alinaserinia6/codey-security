from analyzers.finding import Finding
from phase3.metrics import compute_metrics
from phase3.models import ConfusionMatrix


def test_core_models_import():
    f = Finding(tool="test", rule_id="R1", message="x")
    assert f.tool == "test"
    metrics = compute_metrics(ConfusionMatrix(tp=2, fp=1, fn=1, tn=6))
    assert round(metrics.precision, 6) == round(2 / 3, 6)
    assert round(metrics.recall, 6) == round(2 / 3, 6)
