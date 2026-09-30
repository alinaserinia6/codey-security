"""CWE normalization in the static-tool adapters.

Two bugs lived here, both minting fake CWEs that flowed straight into the
Phase 3 matcher:

* cppcheck's ``_extract_cwe`` scraped the human-readable ``verbose`` message
  for bare numbers, so prose like "In C99 and later ..." or array bounds
  became ``CWE-1018853`` / ``CWE-3`` / ``CWE-0``. Only the structured ``cwe``
  attribute may be read.
* flawfinder's ``_split_cwes`` handled the ``!/`` "or" encoding but not the
  trailing ``!`` (``CWE-362/CWE-367!``), producing ``CWE-367!`` — an id that
  matches nothing and silently voids the finding.
"""
from __future__ import annotations

from analyzers.static_tools import CppcheckRunner, FlawfinderRunner


def test_cppcheck_reads_only_the_structured_cwe_attribute():
    assert CppcheckRunner._extract_cwe("398") == ["CWE-398"]
    assert CppcheckRunner._extract_cwe("CWE-398") == ["CWE-398"]
    assert CppcheckRunner._extract_cwe("") == []
    assert CppcheckRunner._extract_cwe("CWE-119!/CWE-120") == ["CWE-119", "CWE-120"]


def test_cppcheck_rejects_non_numeric_cwe_fragments():
    # A stray "!" or prose fragment must be dropped, not minted.
    assert CppcheckRunner._extract_cwe("CWE-367!") == ["CWE-367"]
    assert CppcheckRunner._extract_cwe("CWE-") == []
    assert CppcheckRunner._extract_cwe("not a cwe") == []


def test_flawfinder_splits_both_or_encodings():
    assert FlawfinderRunner._split_cwes("CWE-119!/CWE-120") == ["CWE-119", "CWE-120"]
    assert FlawfinderRunner._split_cwes("CWE-362/CWE-367!") == ["CWE-362", "CWE-367"]
    assert FlawfinderRunner._split_cwes("CWE-362!/CWE-367!") == ["CWE-362", "CWE-367"]
    assert FlawfinderRunner._split_cwes("") == []
    assert FlawfinderRunner._split_cwes(None) == []


def test_flawfinder_drops_non_cwe_cells():
    assert FlawfinderRunner._split_cwes("race condition") == []
