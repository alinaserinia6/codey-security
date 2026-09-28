"""The CVE catalogue is hand-maintained reference data.

Nothing else in the test suite would notice a CVE that is attached to the wrong
weakness class, and the report is required to name a real related CVE, so the
mapping is checked here against the shape of the data rather than left to
review. The individual CVE-to-CWE assignments were verified against NVD; see the
``notes`` field of ``data/cve_catalog.json``.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from analyzers.catalog import (
    CATALOG_PATH,
    CveEntry,
    CweEntry,
    VulnerabilityCatalog,
    get_catalog,
)

CATALOG = get_catalog()

# CVE ids the proposal names, and the weakness class each one actually is.
# Checked against NVD rather than recalled: CVE-2021-3156 is a heap buffer
# overflow and CVE-2021-25239 is an information-disclosure issue, neither of
# which is what the proposal's example list assumed.
PROPOSAL_CVES = {
    "CVE-2021-3156": "CWE-122",
    "CVE-2017-7529": "CWE-190",
    "CVE-2021-25239": "CWE-200",
    "CVE-2022-22817": "CWE-94",
}


def test_catalog_loads():
    assert len(CATALOG.cwe_ids()) >= 12
    assert len(CATALOG.cve_ids()) >= 4


def test_catalog_is_internally_consistent():
    assert CATALOG.validate() == []


def test_pyyaml_unsafe_deserialization_has_a_verified_reference():
    """The proposal names PyYAML under the wrong CVE, so pin the replacement."""
    fields = CATALOG.report_fields("CWE-502")
    assert fields["related_cves"] == ["CVE-2017-18342"]
    assert CATALOG.cve("CVE-2017-18342").weakness_source == "NVD CWE-502"


def test_out_of_scope_records_cannot_reach_a_report():
    catalog = VulnerabilityCatalog(
        cwes={
            "CWE-200": CweEntry(
                cwe_id="CWE-200",
                name="Information Exposure",
                family="other",
                cves=["CVE-2021-25239"],
            )
        },
        cves={
            "CVE-2021-25239": CveEntry(
                cve_id="CVE-2021-25239",
                project="Trend Micro",
                language="other",
                cwe="CWE-200",
                title="example",
                reference="https://nvd.nist.gov/vuln/detail/CVE-2021-25239",
                in_scope=False,
                out_of_scope_reason="x" * 41,
            )
        },
    )
    assert catalog.validate() == [
        "CVE-2021-25239: marked out of scope but listed under CWE-200"
    ]
    assert catalog.report_fields("CWE-200")["related_cves"] == []


@pytest.mark.parametrize("cve_id,cwe", sorted(PROPOSAL_CVES.items()))
def test_proposal_cves_are_present_and_correctly_mapped(cve_id, cwe):
    entry = CATALOG.cve(cve_id)
    assert entry is not None, f"{cve_id} is named in the proposal but not catalogued"
    assert entry.cwe == cwe


def test_every_cve_carries_a_reference_url():
    for cve_id in CATALOG.cve_ids():
        assert CATALOG.cve(cve_id).reference.startswith("https://"), cve_id


def test_an_out_of_scope_cve_says_why():
    """An excluded example must be auditable, not silently dropped."""
    excluded = [c for c in map(CATALOG.cve, CATALOG.cve_ids()) if not c.in_scope]
    assert excluded, "the Trend Micro record is expected to be marked out of scope"
    for entry in excluded:
        assert len(entry.out_of_scope_reason) > 40


def test_command_injection_is_not_attached_to_a_buffer_overflow_cve():
    """Guards the specific error the catalogue had: Baron Samedit on CWE-78."""
    assert CATALOG.report_fields("CWE-78")["related_cves"] == []
    assert "CVE-2021-3156" in CATALOG.report_fields("CWE-122")["related_cves"]


def test_every_in_scope_cve_class_has_at_least_one_cve():
    """A class with no real-world example still gets a reference, not a CVE."""
    for cwe_id in CATALOG.cwe_ids():
        fields = CATALOG.report_fields(cwe_id)
        assert fields["references"], cwe_id
        assert fields["references"][0].startswith("https://cwe.mitre.org/")


def test_related_cwes_are_all_normalised():
    for cve_id in CATALOG.cve_ids():
        for cwe in CATALOG.cve(cve_id).related_cwes:
            assert re.fullmatch(r"CWE-\d+", cwe), f"{cve_id}: {cwe}"


def test_report_fields_never_invent_a_cve():
    fields = CATALOG.report_fields("CWE-99999")
    assert fields == {"cwe_name": "", "related_cves": [], "references": []}


def test_load_rejects_a_malformed_catalogue(tmp_path):
    bad = tmp_path / "catalog.json"
    bad.write_text(json.dumps({"cwes": [{"name": "no id"}], "cves": []}))
    with pytest.raises(KeyError):
        VulnerabilityCatalog.load(bad)


def test_catalogue_file_parses_and_is_documented():
    payload = json.loads(Path(CATALOG_PATH).read_text(encoding="utf-8"))
    assert payload["schema_version"]
    assert payload.get("notes"), "the mapping decisions should be recorded in the file"
