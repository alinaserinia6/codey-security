# Juliet Benchmark Methodology

## Dataset

Use Juliet Test Suite for C/C++ version 1.3 as the first research benchmark. The NIST SARD record identifies it as a C/C++ dataset containing 64,099 test cases across 118 CWEs.

## Ground truth

The importer uses Juliet's `bad`/`good` filename convention to construct sample-level labels. A `bad` sample is positive; a `good` sample is negative. The importer also records CWE and an optional function/line anchor.

## Leakage prevention

Juliet contains related variants of the same scenario. The importer creates `group_id` values so train/test splitting can keep related variants together.

Juliet also prints its label inside the source. `phase2/sanitize.py` removes
that before any text is shown to the model:

- comments are blanked in place with `phase2/sanitize.py:strip_comments`, so
  `CWE: 190`, `POTENTIAL FLAW` and `good variant` disappear while byte offsets
  and line numbers stay identical to the file the tools reported;
- leaking identifiers (`CWE190_Integer_Overflow__int_..._45_bad`, `badSink`,
  `goodG2B`, `OMITBAD`) are rewritten to stable `sym_<sha1[:6]>` aliases, so
  the same name is rewritten the same way in the snippet, the structural
  evidence and the tool messages;
- `CWE-190`-style references are never rewritten — the matcher needs them.

`tests/test_sanitize.py` guards this. If sanitization regresses, every
LLM-based experiment silently becomes a label-leak rather than a measurement.

## Matching

Phase 3 matches positive findings primarily by source file, then uses CWE overlap and line proximity. The initial benchmark should keep line tolerance fixed before looking at final test metrics.

## Metrics

The current evaluator reports finding-level TP/FP/FN and sample-level TN. Per-CWE metrics use benign Juliet samples associated with the CWE as the negative population for that CWE.

## Recommended reporting

Report:

1. dataset version and checksum
2. number of samples and CWEs
3. train/test split seed and group policy
4. exact analyzer versions
5. LLM model/provider and prompt version
6. all thresholds and line tolerances
7. aggregate and per-CWE metrics
8. examples of false positives and false negatives
