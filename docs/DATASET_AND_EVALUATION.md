# Dataset and evaluation protocol

## Ground-truth schema

Each benchmark sample needs:

- unique `sample_id`
- source `file`
- `vulnerable` boolean
- optional CWE list
- optional line/function/finding identifier
- human-readable description

Example:

```json
{
  "sample_id": "cwe120_001",
  "file": "samples/cwe120_001.c",
  "vulnerable": true,
  "cwe": ["CWE-120"],
  "line": 8,
  "function": "vulnerable_copy",
  "finding_id": "CWE120-STRCPY",
  "description": "Unbounded copy into a fixed-size destination buffer"
}
```

## Matching policy

Predictions are matched greedily against vulnerable ground-truth findings. The matcher can use:

- same sample/file;
- compatible CWE when available;
- line-distance tolerance;
- otherwise a structural fallback.

Keep the matching policy fixed before evaluating competing methods.

## Negative samples

A benign sample is a real negative example. It is not merely a vulnerable sample on which a tool returned no finding.

FPR therefore requires a defined benign population:

`FP / (FP + TN)`.

## Recommended experiment protocol

1. Build one benchmark manifest.
2. Freeze train/dev/test splits if tuning is necessary.
3. Run every method over the same test set.
4. Save raw findings and final predictions.
5. Evaluate with one matcher implementation.
6. Report failures/skips separately.
7. Aggregate only after individual experiment files are immutable.

## Metrics

Primary:

- Precision
- Recall
- F1
- FPR

Secondary:

- Specificity
- Accuracy
- Balanced accuracy
- per-CWE Precision/Recall/F1
- runtime
- model/token cost where available

## Datasets in use

Manifests shipped in `datasets/` (see the README table for counts): VulnLLM-R
C / Python / dataflow / repository splits, PrimeVul test pairs, Big-Vul test
split, `python_bench` (synthetic, six classes) and `proposal_min10`.

Protocol for adding a corpus: import it with `scripts/make_manifest.py`
(SARD / Devign / Big-Vul readers exist) rather than hand-writing hundreds of
ground-truth entries, then audit a statistically meaningful subset of the
generated labels before using the dataset for claims. `python
scripts/run_benchmarks.py --list` reports sample and vulnerable counts for
every manifest, so an empty or one-class import shows up before the run.
