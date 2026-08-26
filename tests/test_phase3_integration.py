from pathlib import Path
from phase3.dataset import GroundTruthDataset
from phase3.extract_predictions import predictions_from_phase1
from phase3.evaluator import evaluate


def test_manifest_and_phase1_report(tmp_path: Path):
    source = tmp_path / "x.c"
    source.write_text("int x;\n", encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    manifest.write_text('{"samples":[{"sample_id":"s1","file":"x.c","vulnerable":true,"cwe":["CWE-120"],"line":1}]}', encoding="utf-8")
    dataset = GroundTruthDataset.from_json(manifest)
    assert dataset.resolve_file(dataset.samples[0]) == source.resolve()
    report = {"source": str(source), "findings": [{"tool":"cppcheck","file":str(source),"line":1,"cwe":["CWE-120"],"confidence":0.9,"fingerprint":"abc"}]}
    predictions = predictions_from_phase1(report, "s1")
    result = evaluate("static", predictions, list(dataset))
    assert result.metrics.confusion.tp == 1
