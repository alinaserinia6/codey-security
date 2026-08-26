from pathlib import Path

from phase3.dataset import GroundTruthDataset
from phase3.juliet.manifest import JulietManifestBuilder
from phase3.juliet.parser import JulietFileParser

FIXTURE = Path(__file__).parent / "fixtures" / "juliet_minimal"


def test_juliet_parser_classifies_bad_and_good():
    parser = JulietFileParser()
    bad = parser.parse(FIXTURE / "testcases/CWE120_Buffer_Overflow/CWE120_Buffer_Overflow__char_array_copy_01_bad.c", root=FIXTURE)
    good = parser.parse(FIXTURE / "testcases/CWE120_Buffer_Overflow/CWE120_Buffer_Overflow__char_array_copy_01_good.c", root=FIXTURE)
    assert bad is not None and bad.vulnerable is True
    assert bad.cwe == ["CWE-120"]
    assert bad.function == "CWE120_bad"
    assert good is not None and good.vulnerable is False
    assert good.cwe == ["CWE-120"]
    assert bad.group_id == good.group_id


def test_juliet_manifest_and_root_resolution(tmp_path: Path):
    manifest = tmp_path / "juliet.json"
    builder = JulietManifestBuilder(FIXTURE)
    payload = builder.write_manifest(manifest, cwes=["CWE-120"])
    assert payload["summary"]["samples"] == 2

    dataset = GroundTruthDataset.from_json(manifest)
    assert dataset.root == FIXTURE.resolve()
    assert len(dataset) == 2
    assert dataset.resolve_file(dataset.samples[0]).exists()
    assert {s.vulnerable for s in dataset} == {True, False}


def test_group_safe_split(tmp_path: Path):
    from phase3.juliet.split import split_manifest
    builder = JulietManifestBuilder(FIXTURE)
    manifest = tmp_path / "manifest.json"
    builder.write_manifest(manifest, cwes=["CWE-120"])
    train = tmp_path / "train.json"
    test = tmp_path / "test.json"
    train_payload, test_payload = split_manifest(manifest, train, test, test_ratio=0.5, seed=42)
    train_groups = {s["group_id"] for s in train_payload["samples"]}
    test_groups = {s["group_id"] for s in test_payload["samples"]}
    assert train_groups.isdisjoint(test_groups)
    assert train_payload["summary"]["samples"] + test_payload["summary"]["samples"] == 2
