"""Corpus loaders for the benchmarks the proposal names.

The thing worth testing here is not the happy path but the failure behaviour: a
loader that quietly treats an unrecognised test case as benign produces a
manifest that looks like ground truth and is not. Each test below pins a case
where the loader must either classify it correctly or refuse it.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from phase3.loaders import (
    FunctionCorpusOptions,
    LoaderError,
    SardOptions,
    load_big_vul,
    load_devign,
    load_function_corpus,
    load_sard,
    write_manifest,
)


# -- SARD ------------------------------------------------------------------

def make_sard(root: Path, layout: dict) -> None:
    for relative, body in layout.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)


def test_sard_labels_vulnerable_and_safe_directories(tmp_path):
    """An explicit marker directory decides the label, in either position."""
    make_sard(
        tmp_path,
        {
            "CWE_120/vulnerable/sard0001.c": "void f(char *s){strcpy(d,s);}\n",
            "CWE_120/safe/sard0002.c": "void f(char *s){snprintf(d,4,\"%s\",s);}\n",
            "CWE_787/good/sard0003.c": "void f(){}\n",
            "CWE_190/unsafe/sard0004.c": "void f(int a,int b){int c=a*b;}\n",
        },
    )
    payload = load_sard(tmp_path)
    labels = {s["sample_id"]: s["vulnerable"] for s in payload["samples"]}
    assert labels == {
        "CWE_120/vulnerable/sard0001.c": True,
        "CWE_120/safe/sard0002.c": False,
        "CWE_787/good/sard0003.c": False,
        "CWE_190/unsafe/sard0004.c": True,
    }
    assert payload["dataset"]["vulnerable_count"] == 2
    assert payload["dataset"]["benign_count"] == 2
    assert payload["dataset"]["per_cwe"] == {
        "CWE-120": 2, "CWE-190": 1, "CWE-787": 1,
    }


def test_sard_derives_the_cwe_from_the_path(tmp_path):
    make_sard(tmp_path, {"CWE_089__sqli/unsafe/sard0001.py": "def f(q): cur.execute(q)\n"})
    payload = load_sard(tmp_path)
    assert payload["samples"][0]["cwe"] == ["CWE-89"]
    assert payload["samples"][0]["language"] == "python"


def test_sard_deduplicates_a_repeated_cwe_in_the_path(tmp_path):
    make_sard(tmp_path, {"CWE_120/CWE_120_unsafe/sard1.c": "int main(){return 0;}\n"})
    payload = load_sard(tmp_path)
    assert payload["samples"][0]["cwe"] == ["CWE-120"]


def test_sard_does_not_guess_a_bare_cwe_directory(tmp_path):
    """The default is strict: no marker directory means no label.

    Treating an unlabelled case as benign would deflate a false-alarm rate, and
    treating it as vulnerable would inflate a recall. Neither is a safe default.
    """
    make_sard(
        tmp_path,
        {
            "CWE_120/sard0001.c": "void f(){}\n",
            "CWE_120/mystery/sard0002.c": "void f(){}\n",
            "CWE_120/safe/sard0003.c": "void f(){}\n",
        },
    )
    payload = load_sard(tmp_path)
    assert [s["sample_id"] for s in payload["samples"]] == ["CWE_120/safe/sard0003.c"]
    assert payload["dataset"]["unclassified_count"] == 2
    assert "CWE_120/sard0001.c" in payload["dataset"]["unclassified"]


def test_sard_can_treat_a_bare_cwe_directory_as_vulnerable(tmp_path):
    """Opt-in support for the release convention that it implies vulnerable."""
    make_sard(
        tmp_path,
        {
            "CWE_120/sard0001.c": "void f(char*s){strcpy(d,s);}\n",
            "CWE_120/good/sard0002.c": "void f(char*s){snprintf(d,4,\"%s\",s);}\n",
            "elsewhere/sard0003.c": "void f(){}\n",
        },
    )
    payload = load_sard(tmp_path, SardOptions(assume_vulnerable=True))
    labels = {s["sample_id"]: s["vulnerable"] for s in payload["samples"]}
    assert labels == {
        "CWE_120/sard0001.c": True,
        "CWE_120/good/sard0002.c": False,
    }
    assert payload["dataset"]["assume_vulnerable"] is True
    # A file outside a CWE directory is still not guessed at.
    assert payload["dataset"]["unclassified_count"] == 1


def test_sard_raises_when_nothing_can_be_classified(tmp_path):
    make_sard(tmp_path, {"mystery/sard0001.c": "void f(){}\n"})
    with pytest.raises(LoaderError, match="no test cases found"):
        load_sard(tmp_path)


def test_sard_raises_on_a_missing_root(tmp_path):
    with pytest.raises(LoaderError, match="does not exist"):
        load_sard(tmp_path / "absent")


def test_sard_raises_on_an_unknown_label_rule(tmp_path):
    make_sard(tmp_path, {"safe/sard1.c": "void f(){}\n"})
    with pytest.raises(LoaderError, match="unknown label_from"):
        load_sard(tmp_path, SardOptions(label_from="guess"))


def test_sard_reads_a_metadata_table_when_asked(tmp_path):
    make_sard(
        tmp_path,
        {
            "CWE_120/sard0001.c": "void f(char*s){strcpy(d,s);}\n",
            "CWE_120/sard0002.c": "void f(char*s){snprintf(d,4,\"%s\",s);}\n",
            "CWE_120/metadata.csv": "ID,Name,Type\n1,sard0001.c,vulnerable\n"
            "2,sard0002.c,safe\n",
        },
    )
    payload = load_sard(tmp_path, SardOptions(label_from="metadata"))
    labels = {s["sample_id"]: s["vulnerable"] for s in payload["samples"]}
    assert labels == {
        "CWE_120/sard0001.c": True,
        "CWE_120/sard0002.c": False,
    }
    assert payload["dataset"]["unclassified_count"] == 0


def test_sard_ignores_files_with_other_extensions(tmp_path):
    make_sard(
        tmp_path,
        {
            "CWE_120/unsafe/sard0001.c": "void f(){}\n",
            "CWE_120/unsafe/README.md": "not a test case\n",
        },
    )
    assert len(load_sard(tmp_path)["samples"]) == 1


def test_sard_respects_a_limit(tmp_path):
    make_sard(
        tmp_path, {f"CWE_120/unsafe/sard{i}.c": "void f(){}\n" for i in range(10)}
    )
    assert len(load_sard(tmp_path, max_samples=4)["samples"]) == 4


# -- Devign / Big-Vul -----------------------------------------------------

def devign_payload(n: int = 3) -> list:
    return [
        {
            "project": f"proj/{i}",
            "func": f"int f{i}(char *p) {{ return atoi(p); }}",
            "target": i % 2,
        }
        for i in range(n)
    ]


def test_devign_writes_one_file_per_function(tmp_path):
    corpus = tmp_path / "devign.json"
    corpus.write_text(json.dumps(devign_payload()))
    out = tmp_path / "fn"
    payload = load_devign(corpus, out_dir=out)

    assert len(payload["samples"]) == 3
    for sample in payload["samples"]:
        path = Path(sample["file"])
        assert path.is_file()
        assert path.suffix == ".c"
        assert "atoi" in path.read_text()
        assert sample["language"] == "c"
    assert payload["dataset"]["granularity"] == "function"


def test_devign_labels_follow_the_target_field(tmp_path):
    corpus = tmp_path / "devign.json"
    corpus.write_text(json.dumps(devign_payload(2)))
    payload = load_devign(corpus, out_dir=tmp_path / "fn")
    assert [s["vulnerable"] for s in payload["samples"]] == [False, True]
    assert payload["dataset"]["vulnerable_count"] == 1


def test_devign_has_no_cwe_annotation(tmp_path):
    corpus = tmp_path / "devign.json"
    corpus.write_text(json.dumps(devign_payload(1)))
    payload = load_devign(corpus, out_dir=tmp_path / "fn")
    assert payload["samples"][0]["cwe"] == []
    assert payload["dataset"]["per_cwe"] == {}


def test_big_vul_splits_a_packed_cwe_field(tmp_path):
    corpus = tmp_path / "big_vul.json"
    corpus.write_text(
        json.dumps(
            [
                {"project": "x", "func": "void f(char*s){strcpy(d,s);}", "target": 1,
                 "cwe": "119, 120, 787"},
                {"project": "y", "func": "void g(){}", "target": 0, "cwe": "CWE-190"},
                {"project": "z", "func": "void h(){}", "target": 0, "cwe": None},
            ]
        )
    )
    payload = load_big_vul(corpus, out_dir=tmp_path / "fn")
    assert payload["samples"][0]["cwe"] == ["CWE-119", "CWE-120", "CWE-787"]
    assert payload["samples"][1]["cwe"] == ["CWE-190"]
    assert payload["samples"][2]["cwe"] == []
    assert payload["dataset"]["per_cwe"] == {
        "CWE-119": 1, "CWE-120": 1, "CWE-190": 1, "CWE-787": 1,
    }


def test_function_corpus_drops_duplicate_sources(tmp_path):
    corpus = tmp_path / "devign.json"
    record = {"project": "p", "func": "int f(){return 0;}", "target": 0}
    corpus.write_text(json.dumps([record, dict(record), dict(record)]))
    payload = load_devign(corpus, out_dir=tmp_path / "fn")
    assert len(payload["samples"]) == 1


def test_function_corpus_keeps_duplicates_when_asked(tmp_path):
    corpus = tmp_path / "devign.json"
    record = {"project": "p", "func": "int f(){return 0;}", "target": 0}
    corpus.write_text(json.dumps([record, dict(record)]))
    options = FunctionCorpusOptions(drop_duplicates=False)
    payload = load_devign(corpus, options=options, out_dir=tmp_path / "fn")
    assert len(payload["samples"]) == 2


def test_function_corpus_counts_records_with_no_source(tmp_path):
    corpus = tmp_path / "devign.json"
    corpus.write_text(
        json.dumps([{"project": "p", "func": "   ", "target": 1}])
    )
    with pytest.raises(LoaderError, match="no usable records"):
        load_devign(corpus, out_dir=tmp_path / "fn")


def test_function_corpus_accepts_a_wrapped_list(tmp_path):
    corpus = tmp_path / "devign.json"
    corpus.write_text(json.dumps({"data": devign_payload(2)}))
    assert len(load_devign(corpus, out_dir=tmp_path / "fn")["samples"]) == 2


def test_function_corpus_raises_on_a_missing_file(tmp_path):
    with pytest.raises(LoaderError, match="does not exist"):
        load_devign(tmp_path / "absent.json", out_dir=tmp_path / "fn")


def test_function_corpus_raises_on_an_unexpected_shape(tmp_path):
    corpus = tmp_path / "devign.json"
    corpus.write_text(json.dumps({"unexpected": "shape"}))
    with pytest.raises(LoaderError):
        load_devign(corpus, out_dir=tmp_path / "fn")


def test_label_noise_is_disclosed_in_the_manifest(tmp_path):
    """A number measured on these labels must not be quotable as ground truth."""
    corpus = tmp_path / "devign.json"
    corpus.write_text(json.dumps(devign_payload(2)))
    payload = load_devign(corpus, out_dir=tmp_path / "fn")
    limitations = payload["dataset"]["limitations"]
    assert "noise" in limitations
    assert "not a verified ground truth" in limitations


# -- manifests ------------------------------------------------------------

def test_manifest_round_trips_through_the_dataset_reader(tmp_path):
    """A generated manifest has to load with the code that consumes it."""
    from phase3.dataset import GroundTruthDataset

    corpus = tmp_path / "devign.json"
    corpus.write_text(json.dumps(devign_payload(2)))
    payload = load_devign(corpus, out_dir=tmp_path / "fn")
    path = write_manifest(payload, tmp_path / "manifest.json")

    dataset = GroundTruthDataset.from_json(path)
    assert len(dataset) == 2
    assert dataset.languages() == ["c"]
    for sample in dataset:
        assert dataset.resolve_file(sample).is_file()


def test_write_manifest_creates_parent_directories(tmp_path):
    path = write_manifest({"dataset": {}, "samples": []}, tmp_path / "a" / "b" / "m.json")
    assert path.is_file()
