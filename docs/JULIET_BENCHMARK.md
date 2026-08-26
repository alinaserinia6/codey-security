# Juliet Benchmark Methodology

## Dataset

Use Juliet Test Suite for C/C++ version 1.3 as the first research benchmark. The NIST SARD record identifies it as a C/C++ dataset containing 64,099 test cases across 118 CWEs.

## Ground truth

The importer uses Juliet's `bad`/`good` filename convention to construct sample-level labels. A `bad` sample is positive; a `good` sample is negative. The importer also records CWE and an optional function/line anchor.

## Leakage prevention

Juliet contains related variants of the same scenario. The importer creates `group_id` values so train/test splitting can keep related variants together.

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
