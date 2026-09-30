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
    RealWorldOptions,
    SardOptions,
    VulnLLMROptions,
    load_big_vul,
    load_bigvul_hf,
    load_devign,
    load_function_corpus,
    load_primevul,
    load_sard,
    load_vulnllm_r,
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


# -- PrimeVul / Big-Vul HF layouts ------------------------------------------
#
# These pin the real Hugging Face schemas (PrimeVul JSONL with a ``cwe`` list,
# Big-Vul rows with ``func_before``/``func_after``/``vul``/``CWE ID``), which
# the legacy ``func``/``target`` loader cannot read. The properties under test:
# good and bad stay separate (variants + balanced classes), empty sources are
# refused rather than scored as benign, and only selected samples get files.

PRIMEVUL_ROWS = [
    {"idx": 1, "project": "proj", "commit_id": "aaa",
     "func": "void bad(){strcpy(d,s);}", "target": 1,
     "cwe": ["CWE-120"], "cve": "CVE-2020-0001"},
    {"idx": 2, "project": "proj", "commit_id": "aaa",
     "func": "void good(){snprintf(d,4,\"%s\",s);}", "target": 0,
     "cwe": ["CWE-120"], "cve": "CVE-2020-0001"},
    {"idx": 3, "project": "proj", "commit_id": "bbb",
     "func": "   ", "target": 1, "cwe": ["CWE-190"], "cve": ""},
    {"idx": 4, "project": "proj", "commit_id": "ccc",
     "func": "void mystery(){return;}", "target": 1, "cwe": [], "cve": ""},
]


def write_jsonl(path: Path, rows: list) -> None:
    import json as _json

    path.write_text("\n".join(_json.dumps(r) for r in rows) + "\n")


def test_primevul_separates_good_and_bad(tmp_path):
    corpus = tmp_path / "pv.jsonl"
    write_jsonl(corpus, PRIMEVUL_ROWS)
    payload = load_primevul(
        corpus, out_dir=tmp_path / "fn", options=RealWorldOptions(relative_to=tmp_path)
    )
    by_id = {s["sample_id"]: s for s in payload["samples"]}
    assert by_id["primevul_1_bad"]["vulnerable"] is True
    assert by_id["primevul_1_bad"]["cwe"] == ["CWE-120"]
    assert by_id["primevul_1_bad"]["variant"] == "bad"
    assert by_id["primevul_2_good"]["vulnerable"] is False
    assert by_id["primevul_2_good"]["variant"] == "good"
    assert payload["dataset"]["vulnerable_count"] == 1
    assert payload["dataset"]["benign_count"] == 1


def test_primevul_refuses_empty_and_cweless_vulnerable(tmp_path):
    """An empty function is a missing sample, not a benign one; a vulnerable
    row without a CWE is left out rather than guessed at."""
    corpus = tmp_path / "pv.jsonl"
    write_jsonl(corpus, PRIMEVUL_ROWS)
    payload = load_primevul(corpus, out_dir=tmp_path / "fn")
    assert payload["dataset"]["skipped_empty"] == 1
    assert payload["dataset"]["skipped_no_cwe"] == 1
    assert len(payload["samples"]) == 2


def test_primevul_writes_files_only_for_selected_samples(tmp_path):
    corpus = tmp_path / "pv.jsonl"
    rows = [
        {"idx": i, "project": "p", "commit_id": "c",
         "func": f"void f{i}(){{return;}}", "target": 0, "cwe": [], "cve": ""}
        for i in range(6)
    ] + [PRIMEVUL_ROWS[0]]
    write_jsonl(corpus, rows)
    payload = load_primevul(corpus, out_dir=tmp_path / "fn")
    # 1 vulnerable vs 6 benign -> balanced down to 1+1.
    assert len(payload["samples"]) == 2
    assert len(list((tmp_path / "fn").glob("*.c"))) == 2
    for sample in payload["samples"]:
        assert (tmp_path / "fn" / Path(sample["file"]).name).is_file()


def test_primevul_relative_paths_resolve_from_the_manifest_dir(tmp_path):
    from phase3.dataset import GroundTruthDataset

    corpus = tmp_path / "pv.jsonl"
    write_jsonl(corpus, PRIMEVUL_ROWS[:2])
    manifest_dir = tmp_path / "ds"
    manifest_dir.mkdir()
    payload = load_primevul(
        corpus,
        out_dir=manifest_dir / "pv_functions",
        options=RealWorldOptions(relative_to=manifest_dir),
    )
    path = write_manifest(payload, manifest_dir / "pv.json")
    dataset = GroundTruthDataset.from_json(path)
    assert len(dataset) == 2
    for sample in dataset:
        assert dataset.resolve_file(sample).is_file()
        assert not Path(sample.file).is_absolute()


BIGVUL_ROWS = [
    {"project": "x", "commit_id": "c1", "vul": 1, "CWE ID": "CWE-119",
     "CVE ID": "CVE-2020-0002",
     "func_before": "void f(char*s){strcpy(d,s);}",
     "func_after": "void f(char*s){snprintf(d,4,\"%s\",s);}"},
    {"project": "y", "commit_id": "c2", "vul": 0, "CWE ID": "",
     "CVE ID": "", "func_before": "void g(){return;}", "func_after": ""},
]


def test_bigvul_hf_emits_a_fix_twin_for_vulnerable_rows(tmp_path):
    corpus = tmp_path / "bv.json"
    corpus.write_text(json.dumps(BIGVUL_ROWS))
    payload = load_bigvul_hf(
        corpus, out_dir=tmp_path / "fn",
        options=RealWorldOptions(balanced=False),
    )
    variants = sorted(
        (s["variant"], s["vulnerable"]) for s in payload["samples"]
    )
    assert ("bad", True) in variants
    assert ("good", False) in variants
    bad = next(s for s in payload["samples"] if s["variant"] == "bad")
    assert bad["cwe"] == ["CWE-119"]
    assert bad["group_id"] == "x_c1"
    twin = next(
        s for s in payload["samples"]
        if s["variant"] == "good" and s["group_id"] == "x_c1"
    )
    assert "snprintf" in Path(twin["file"]).read_text()


def test_bigvul_hf_without_fix_twin_uses_benign_rows(tmp_path):
    corpus = tmp_path / "bv.json"
    corpus.write_text(json.dumps(BIGVUL_ROWS))
    payload = load_bigvul_hf(
        corpus, out_dir=tmp_path / "fn",
        options=RealWorldOptions(balanced=False, include_fix_as_benign=False),
    )
    assert sorted(s["vulnerable"] for s in payload["samples"]) == [False, True]


def test_bigvul_hf_cwe_filter_and_limit(tmp_path):
    corpus = tmp_path / "bv.json"
    corpus.write_text(json.dumps(BIGVUL_ROWS))
    payload = load_bigvul_hf(
        corpus, out_dir=tmp_path / "fn",
        options=RealWorldOptions(cwe_filter=["CWE-119"], limit=1),
    )
    assert len(payload["samples"]) == 1
    assert payload["dataset"]["cwe_filter"] == ["CWE-119"]


def test_bigvul_hf_rejects_mislabelled_rows(tmp_path):
    corpus = tmp_path / "bv.json"
    corpus.write_text(json.dumps(
        [{"project": "x", "vul": 1, "CWE ID": "", "func_before": "void f(){}"}]
    ))
    with pytest.raises(LoaderError, match="no usable records"):
        load_bigvul_hf(corpus, out_dir=tmp_path / "fn")


# -- VulnLLM-R layout --------------------------------------------------------

VULNLLM_R_ROWS = [
    {"idx": 1, "language": "c", "function_name": "copy",
     "code": "void copy(char*d,char*s){strcpy(d,s);}", "target": 1,
     "CWE_ID": ["CWE-120"], "RELATED_CWE": ["CWE-119"]},
    {"idx": 2, "language": "c", "function_name": "copy",
     "code": "void copy(char*d,char*s){snprintf(d,4,\"%s\",s);}", "target": 0,
     "CWE_ID": ["CWE-120"], "RELATED_CWE": ["CWE-119"]},
    {"idx": 3, "language": "python", "function_name": "run",
     "code": "import os\nos.system(cmd)\n", "target": 1,
     "CWE_ID": ["CWE-78"], "RELATED_CWE": []},
    {"idx": 4, "language": "java", "function_name": "Run",
     "code": "void run(){exec(cmd);}", "target": 0,
     "CWE_ID": ["CWE-78"], "RELATED_CWE": []},
    {"idx": 5, "language": "c", "function_name": "empty",
     "code": "  ", "target": 1, "CWE_ID": ["CWE-190"], "RELATED_CWE": []},
]


def test_vulnllm_r_groups_files_by_cwe_and_verdict(tmp_path):
    corpus = tmp_path / "vr.json"
    corpus.write_text(json.dumps(VULNLLM_R_ROWS))
    payload = load_vulnllm_r(
        corpus, out_dir=tmp_path / "vr",
        options=VulnLLMROptions(languages=["c", "python", "java"],
                                relative_to=tmp_path),
    )
    assert len(payload["samples"]) == 4
    assert payload["dataset"]["skipped_empty"] == 1
    paths = sorted(s["file"] for s in payload["samples"])
    assert paths[0].startswith("vr/function_level/c/CWE-120/bad/")
    assert paths[1].startswith("vr/function_level/c/CWE-120/good/")
    assert paths[2].startswith("vr/function_level/java/CWE-78/good/")
    assert paths[3].startswith("vr/function_level/python/CWE-78/bad/")
    bad = next(s for s in payload["samples"] if s["variant"] == "bad")
    assert bad["group_id"] == "CWE-120"
    assert bad["related_cwe"] == ["CWE-119"]


def test_vulnllm_r_leaves_java_out_of_a_scored_manifest(tmp_path):
    """No analyzer in this project reads Java; scoring it would count every
    sample as a miss for reasons unrelated to detection."""
    corpus = tmp_path / "vr.json"
    corpus.write_text(json.dumps(VULNLLM_R_ROWS))
    payload = load_vulnllm_r(corpus, out_dir=tmp_path / "vr")
    assert payload["dataset"]["languages"] == ["c", "python"]
    assert payload["dataset"]["skipped_language"] == 1
    assert {s["language"] for s in payload["samples"]} == {"c", "python"}


def test_vulnllm_r_suffix_follows_language(tmp_path):
    corpus = tmp_path / "vr.json"
    corpus.write_text(json.dumps(VULNLLM_R_ROWS))
    payload = load_vulnllm_r(
        corpus, out_dir=tmp_path / "vr",
        options=VulnLLMROptions(languages=["c", "python"]),
    )
    suffixes = {Path(s["file"]).suffix for s in payload["samples"]}
    assert suffixes == {".c", ".py"}
