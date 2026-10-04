# Codey Security

**Evidence-driven vulnerability analysis for Python and C/C++.**

Codey Security combines deterministic program analysis with LLM-based security
reasoning and empirical evaluation. The project is organized into three
completed development phases:

1. **Phase 1 — Structural + Static Analysis**: parse source code with
   Tree-sitter and normalize findings from Bandit, Cppcheck, and Flawfinder.
   A source-to-sink taint tracker runs over the same
   structural index and recovers concrete dataflow chains.
2. **Phase 2 — Multi-Agent Evidence-Aware Verification**: a **Scanner Agent**
   reads the file and proposes candidate vulnerabilities, then a **Verifier
   Agent** checks each candidate against the recovered source-to-sink chain and
   rejects by default. Only the verifier's output can become a reported
   finding, and its rejections are recorded. The original one-agent-per-group
   path is kept as `--architecture single_agent` for the comparison.
3. **Phase 3 — Benchmark + Evaluation**: compare predictions against ground
   truth and calculate Precision, Recall, F1, FPR, specificity, accuracy, and
   per-CWE results.

> **Repository status:** Research prototype, active development. Preserve your
> existing application/UI files from your GitHub checkout when merging this
> research core.

---

## Research objective

The project is designed around the following research question:

> **Can deterministic structural/static evidence combined with LLM-based
> security verification reduce false positives in source-code vulnerability
> detection compared with static analysis or LLM-only approaches?**

The architecture intentionally separates evidence generation from LLM judgment.
This makes it possible to run controlled baselines and ablation experiments
instead of only reporting qualitative examples.

---

## Architecture

```text
                         ┌──────────────────────┐
                         │    Python / C / C++   │
                         └──────────┬───────────┘
                                    │
                           Phase 1  ▼
                    ┌────────────────────────────┐
                    │ Tree-sitter structural AST │
                    │ functions / calls / imports│
                    │ branches / parse errors    │
                    └────────────┬───────────────┘
                                 │
              ┌──────────────────┼──────────────────┐
              │                  │                  │
              ▼                  ▼                  ▼
          Bandit             Cppcheck          Flawfinder
          Python             C / C++            C / C++
                    ┌────────────────────────┐
                    │ Finding normalization   │
                    │ + deduplication         │
                    │ + correlation           │
                    └────────────┬───────────┘
                                 │
                            Phase 2 ▼
                     ┌────────────────────────┐
                     │ Scanner Agent          │
                     │ whole file, proposes  │
                     │ hypotheses             │
                     └────────────┬───────────┘
                                  │ hypotheses
                     ┌────────────▼───────────┐
                     │ Verifier Agent         │
                     │ one at a time, shown   │
                     │ the source-to-sink     │
                     │ chain; rejects by      │
                     │ default                │
                     └────────────┬───────────┘
                                  │
                    CONFIRMED / REJECTED /
                           UNCERTAIN
                                 │
                           Phase 3 ▼
                    ┌────────────────────────┐
                    │ Ground truth benchmark │
                    │ Finding matcher        │
                    │ Precision / Recall / F1│
                    │ FPR / specificity      │
                    │ Per-CWE analysis       │
                    │ Experiment comparison  │
                    └────────────────────────┘
```

The two agents are given deliberately different jobs, and that separation is
what makes the false-alarm reduction measurable: the scanner is tuned for
recall and is expected to propose things that turn out to be wrong, and the
verifier absorbs that over-generation instead of letting it reach the report.
The verifier is not shown the scanner's reasoning, only the hypothesis, because
showing it the argument for a claim tends to anchor the verdict on that claim.

Two conditions the verifier must satisfy are enforced in code rather than left
to the prompt, since a prompt instruction is only a request:

- a reported injection class must have a real source-to-sink chain behind it
  (`--allow-unproven-chains` ablates this), and
- a confirmation below the confidence threshold is downgraded rather than
  reported.

Classes the taint engine does not model — a raw integer overflow, for instance —
are exempt from the chain requirement, because there is no chain to check.

---

## Project structure

```text
codey-security/
├── analyzers/                      # Phase 1 deterministic analysis
│   ├── finding.py                  # canonical finding model + correlation
│   ├── structural_analyzer.py      # Tree-sitter AST/structure extraction
│   ├── taint.py                    # source-to-sink chain recovery
│   ├── catalog.py                  # CWE/CVE reference data
│   ├── static_tools.py             # Bandit/Cppcheck/Flawfinder adapters
│   └── phase1_pipeline.py          # unified Phase 1 pipeline
│
├── data/
│   └── cve_catalog.json            # hand-maintained, NVD-verified CVE mappings
│
├── agents/                         # LLM agents
│   ├── security_agent.py           # shared LLM transport
│   ├── scanner_agent.py            # Scanner role: proposes hypotheses
│   └── verifier_agent.py           # Verifier role: confirms or rejects
│
├── phase2/                         # Phase 2 orchestration
│   ├── models.py
│   ├── prompts.py                  # Scanner and Verifier prompt text
│   ├── context.py                  # sanitized source window for the agent
│   ├── sanitize.py                 # removes dataset label leaks
│   ├── multiagent.py               # Scanner -> Verifier orchestration
│   ├── client.py                   # binds the role agents to the pipeline
│   ├── llm.py
│   └── pipeline.py                 # single-agent baseline, for comparison
│
├── phase3/                         # Phase 3 benchmark/evaluation
│   ├── models.py
│   ├── dataset.py
│   ├── matcher.py
│   ├── metrics.py
│   ├── evaluator.py
│   ├── extract_predictions.py
│   ├── runner.py
│   ├── report.py
│   └── aggregate.py
│
├── scripts/                        # reproducible benchmark entry points
│   ├── doctor.py                   # environment check
│   ├── run_benchmarks.py           # the full ladder: --list / --dry-run /
│   │                               #   suites + legs + dataset selection
│   ├── filter_manifest.py          # subset / language / CWE filters
│   ├── eval_taint_evidence.py      # experiment E (taint evidence vs tool)
│   ├── make_stratified_subset.py   # stratified subset from any manifest
│   ├── run_llm_only_benchmark.py   # experiment B (LLM only)
│   └── evaluate_llm_only.py        # score experiment B with the shared matcher
│
├── examples/                       # small sanity-check samples
├── datasets/                       # benchmark manifests (VulnLLM-R, PrimeVul,
│                                   #   Big-Vul, Python, proposal_min10)
├── results/                        # generated reports (gitignored)
├── codey_security.py               # unified CLI
├── env_config.py                   # runtime configuration + scenarios
├── dataset_schema.json
├── requirements.txt
├── pyproject.toml
├── .env.example
└── README.md
```

---

## Supported languages

| Language | Structural analysis | Security/static baseline |
|---|---|---|
| Python | Tree-sitter | Bandit |
| C | Tree-sitter | Cppcheck, Flawfinder |
| C++ | Tree-sitter | Cppcheck, Flawfinder |

Clang Static Analyzer was evaluated during Phase 1 but is not integrated: in
standalone-file mode it needs a build context, so its results would not be
comparable with the pattern-based tools. For real repositories with build
systems a future Phase 1 could consume `compile_commands.json`, but no Clang
adapter exists in this codebase.

---

## Installation

### 1. System packages

Ubuntu/Debian example:

```bash
sudo apt update
sudo apt install -y python3 python3-venv cppcheck flawfinder
```

Verify:

```bash
cppcheck --version
flawfinder --version
```

### 2. Python environment

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 3. LLM

Phase 2 talks to a running **OpenCode server** through its session API — not
to a raw OpenAI-compatible endpoint. Start one and point the pipeline at it:

```bash
lingling serve --port 4096 --hostname 127.0.0.1
cp .env.example .env   # then set LLM_BASE_URL, LLM_MODEL_ID, LLM_PROVIDER_ID
```

| Variable | Meaning | Default |
|---|---|---|
| `LLM_BASE_URL` | OpenCode server URL | `http://127.0.0.1:4096` |
| `LLM_MODEL_ID` | model id understood by that server | `opencode/deepseek-v4-flash-free` |
| `LLM_PROVIDER_ID` | provider id on that server | `opencode` |
| `LLM_MODE` | agent mode | `build` |
| `LLM_TIMEOUT` | per-request timeout (seconds) | `300` |
| `LLM_REUSE_SESSION` | reuse one session across findings | `false` |

`LLM_MODEL` is accepted as an alias for `LLM_MODEL_ID` because that is the
name used in older `.env` files.

The model id must exist on the configured provider — check it with
`curl -s $LLM_BASE_URL/provider`. Phase 1 and Phase-1-only Phase 3 runs never
contact the server.

> If the server sits behind an HTTP proxy, the provider host must be
> reachable through it (or listed in `no_proxy`); otherwise every Phase 2
> call fails after the timeout with `Cannot connect to API`.

---

## Quick start

All runtime settings (source paths, dataset paths, model name, concurrency)
are configured in `env_config.py` and `.env`. The CLI only selects a scenario.

```bash
python codey_security.py phase1   # structural + static analysis of a file
python codey_security.py phase2   # Phase 1 + Scanner/Verifier verification
python codey_security.py phase3   # benchmark against a ground-truth dataset
python codey_security.py full     # Phase 1 -> Phase 2 -> Phase 3
```

The `codey_security` entry point honours `PHASE2_ARCHITECTURE`, which is
`multi_agent` by default. The two pipelines consume the same Phase 1 report and
the same evidence, so setting it to `single_agent` is what isolates the
contribution of splitting the roles:

```bash
PHASE2_ARCHITECTURE=single_agent python codey_security.py full
```

For running Phase 2 over a directory of Phase 1 reports, with explicit
arguments rather than `.env`, use the dedicated runner:

```bash
python scripts/run_phase2.py results/ --architecture multi_agent \
  --out results/phase2_report.json
python scripts/run_phase2.py results/phase1_report.json \
  --architecture single_agent --out results/phase2_single.json
```

There are intentionally no `--provider`, `--out`, `--dataset` or `--mode`
flags on the `codey_security` CLI. See `README_CLI_CONFIG.md`.

---

## Phase 1 output

A Phase 1 report contains normalized findings plus structural evidence:

```json
{
  "source": "/project/example.cpp",
  "language": "cpp",
  "findings": [
    {
      "tool": "flawfinder",
      "rule_id": "strcpy",
      "file": "/project/example.cpp",
      "line": 12,
      "severity": "HIGH",
      "cwe": ["CWE-120"],
      "evidence": "strcpy(buffer, input);"
    }
  ],
  "metadata": {
    "structure": {
      "parser": "tree-sitter",
      "functions": [],
      "calls": [],
      "imports": [],
      "dangerous_calls": []
    },
    "correlated_findings": []
  }
}
```

### Correlation rules

`metadata.correlated_findings` groups findings that likely describe the same
underlying issue. Two findings are grouped when they are in the same file and
either:

1. belong to the **same function scope** and share at least one CWE, or
2. fall within a small line window and share a CWE or rule family.

Each group's canonical location is the **highest-severity member** of the
group (ties broken by earliest line), so Phase 2 reviews the dangerous
operation rather than an arbitrary line in the cluster.

This format is the contract consumed by Phase 2.

---

## Phase 2 decision model

Phase 2 is two agents with different jobs.

**Scanner Agent** — reads the whole file and returns a list of candidate
vulnerabilities. It receives the source, the structural index (functions,
parameters, dangerous calls, imports), the normalized static-tool findings, and
the recovered dataflow chains, so it does not spend its whole budget
rediscovering a path that is already known. It is not asked to prove anything.
It returns a list of hypotheses, each with a CWE, a line, and a claim.

**Verifier Agent** — handles one hypothesis at a time and is the only agent
whose output can become a report finding. It receives the hypothesis, a window
of source around it, the chains near it, and the nearby static-tool findings.
It returns exactly one of:

- `CONFIRMED` — supplied evidence is sufficient to support the finding.
- `REJECTED` — supplied evidence contradicts the finding or shows it benign.
- `UNCERTAIN` — evidence is insufficient for either conclusion.

`UNCERTAIN` is intentional. The system should not invent certainty when the
evidence is insufficient. Every response also carries a confidence score, a
short technical explanation, explicit supporting evidence, a list of missing
evidence items, and whether the source-to-sink chain was actually verified.

A `CONFIRMED` verdict is only reported if it also survives the code-level
evidence gate: the confidence threshold, the verifier's own
`chain_verified` claim, and — for a class the taint engine models — the
existence of a real source-to-sink chain in the file. Candidates that do not
survive are written to `decisions` with the reason, so the report accounts for
every hypothesis the scanner raised.

Note that the taint engine is used by the multi-agent pipeline and by
`scripts/eval_taint_evidence.py`, not by the single-agent pipeline that produced
the A–D experiment results. Those two sets of numbers measure different things:
A–D ask how well a model judges static findings, while `exp_E` asks how much
signal the deterministic evidence engine carries on its own.

Phase 2 is powered by an OpenCode session (`LLM_BASE_URL`, `LLM_MODEL_ID`,
`LLM_PROVIDER_ID`). The model is recorded in every Phase 3 result under
`metadata.provenance`.

Before any text reaches the model, `phase2/sanitize.py` removes label leaks
from the evidence packet: ground-truth comments (`CWE: 190`, `POTENTIAL FLAW`)
are blanked in place so line numbers stay valid, and scenario identifiers such
as `CWE190_Integer_Overflow__int_45_bad`, `badSink` and `goodG2B` are rewritten
to stable `sym_<hash>` aliases. Without this, an LLM-only baseline would read
the ground-truth label straight out of the file.

---

## Phase 3 evaluation

The benchmark layer supports finding-level matching against ground truth.

Primary metrics:

\[
Precision = \frac{TP}{TP + FP}
\]

\[
Recall = \frac{TP}{TP + FN}
\]

\[
F1 = 2 \cdot \frac{Precision \cdot Recall}{Precision + Recall}
\]

\[
FPR = \frac{FP}{FP + TN}
\]

The implementation also reports specificity, false-negative rate, accuracy,
balanced accuracy, positive/negative support, and per-CWE results.

**Important:** TP/FP/FN are finding-level quantities, while TN requires an
explicit benign/negative sample population. Do not report a single FPR from a
vulnerable-only dataset.

**Granularity.** Precision, recall and F1 are derived from
`metrics.confusion`, where `FP` counts *findings*. The four benign-side rates
above — FPR, specificity, accuracy and balanced accuracy — are derived
instead from `metrics.sample_confusion`, in which every cell counts *files*,
so their `FP` means "benign files flagged", not "findings on benign files".
`negative_support` is the number of benign files. Each result file records the
split as `metadata.metric_granularity`; blending the two matrices inside one
rate makes the denominator move with the number of findings a run happens to
emit, which is how the static baseline could otherwise end up with the worst
balanced accuracy of the four while its finding-level precision told a
different story.

### Two matching protocols, reported side by side

Matching runs in two variants, both scored from the same stored reports, so
the second column never costs a re-run:

| variant | rule | what it answers |
|---|---|---|
| **CWE-strict** (primary, `SCENARIO_PHASE3_REQUIRE_CWE=true`) | file + line + compatible CWE | the corpus's own CWE-strict convention (VulnLLM-R reports it too) |
| CWE-agnostic (secondary) | file + line | pure localization, independent of CWE vocabulary |

The gap is large and it is a property of the labels, not of the analyzers: on
`vulnllm_r_c` only ~31% of ground-truth CWEs are ever emitted by any of the
tools (the tools shout `CWE-327`/`CWE-120`, the labels say
`CWE-476`/`CWE-787`/`CWE-125`), so strict recall is capped near that value.
Static-tool rows read about `.13/.16` (mean P/R) strict and `.28/.36`
agnostic; the deterministic taint evidence averages `.55/.32` strict.

Generate the secondary table from any result file without touching the
primary one:

```bash
python scripts/recompute_result.py --no-cwe-match --out results/agnostic \
    results/exp_vulnllm_r_c_static.json
```

Every protocol choice applies to **all** legs (A–E) of a comparison; never
mix variants across rows of one table, and never select a variant after
looking at the test set without saying so in the write-up.

### Shipped results

Every other run in `results/` is local scratch and stays out of git. These
files are version controlled because they are the evidence behind the thesis
tables:

| file | what it is |
|---|---|
| `results/exp_A_static_subset600.json` | Phase 1 on the 600-sample Juliet subset (table 4.2, row A) |
| `results/exp_B_llm_only_eval600.json` | LLM only, no static evidence (table 4.2, row B) |
| `results/exp_C_static_llm_subset600.json` | static findings + LLM (table 4.2, row C) |
| `results/exp_D_static_structural_llm_subset600.json` | static + structural evidence + LLM (table 4.2, row D) |
| `results/exp_A_static.json` | Phase 1 on all 4098 Juliet files (section 4.8) |
| `results/exp_E_taint_evidence.json` | taint evidence on the Juliet subset (table 4.6) |
| `results/exp_F_python_bench.json` | taint evidence on the Python benchmark (table 4.5) |
| `results/exp_G_devign_taint_full.json` | taint evidence on every Devign function (table 4.6) |
| `results/exp_G_devign_taint_strat600.json` | taint evidence + Flawfinder on a balanced Devign 600 (table 4.6) |
| `results/comparison_all.csv` | the aggregated A/B/C/D comparison |
| `datasets/eval_subset_600.json` | the 600-sample population A–E were scored against |
| `datasets/juliet_test.json` | the full 4098-file Juliet population (section 4.8) |

`datasets/eval_subset_600.json` and `datasets/juliet_test.json` were rebuilt
from the stored reports of `exp_A_static_subset600.json` and
`exp_A_static.json` after the original Juliet manifest was lost; the evaluator
reproduces A, B, C and D from them exactly, including the per-CWE breakdown.

All five of `results/exp_A_static_subset600.json`,
`results/exp_B_llm_only_eval600.json`,
`results/exp_C_static_llm_subset600.json`,
`results/exp_D_static_structural_llm_subset600.json` and
`results/exp_A_static.json` carry a `metrics_recomputed_at` provenance stamp:
their metrics were refreshed with the current evaluator. The refresh corrected
config A's false-positive counting, which now counts every reported finding
rather than one per benign file. B, C and D were unaffected by that particular
correction because each of their benign files carried exactly one finding, but
they were re-scored at the same time so that all four A–D files share one
`metric_granularity` note, one sample-level confusion matrix and one set of
per-CWE counters. Config B stores no per-sample reports — it is scored from its
verdicts alone — so its stamp reads `metrics_recomputed_from:
metadata.matches + metadata.unmatched_predictions` instead of
`metadata.reports`.

Re-derive any of them from the stored per-sample reports without re-running
the analyzers or the model:

```bash
python scripts/recompute_result.py results/exp_C_static_llm_subset600.json
```

`results/exp_B_llm_only_eval600.json` has no per-sample reports to rebuild
from; the same command still works on it, reading the prediction set back out
of its `matches` and `unmatched_predictions`.

---

## Recommended research experiments

| Experiment | Evidence | LLM reasoning | Purpose |
|---|---|---|---|
| A | Static tools | No | baseline |
| B | Source code | LLM only | LLM baseline |
| C | Static findings | Yes | static + LLM |
| D | Static findings + structural evidence | Yes | proposed system |

For each experiment report:

- Precision
- Recall
- F1
- False Positive Rate
- Runtime
- LLM/token cost, when available
- per-CWE breakdown

Use the same benchmark split for every experiment.

### Running them

`scripts/run_benchmarks.py` drives the whole ladder. Nothing is hard-coded:
you choose the suites, the legs, the datasets and the manifest the LLM subset
is cut from. Discover what is available first, dry-run it, then run:

```bash
# what can I run?  (suites, legs, datasets with sample/vuln counts, model, budget)
python scripts/run_benchmarks.py --list

# see the exact commands without executing anything
python scripts/run_benchmarks.py --dry-run --suite all

# deterministic only -- no API key needed (A on every dataset + E taint)
python scripts/run_benchmarks.py --suite static,taint

# the LLM ladder on a 60-sample subset of the C dataflow manifest (A+B+C+D)
python scripts/run_benchmarks.py --suite llm --llm-source vulnllm_r_c_dataflow \
  --llm-limit 60 --concurrency 4 --tag c60

# judge the Python population with the model instead of only the tools
python scripts/run_benchmarks.py --suite llm --llm-source vulnllm_r_python \
  --llm-limit 30 --tag py30

# pick individual legs inside a suite
python scripts/run_benchmarks.py --suite llm --legs C,D --tag ablate_cd
```

For a run against the local jev OpenCode server (slow: ~5 min/sample end to
end, so overnight), `scripts/run_llm_jev.sh` presets the endpoint, the model,
the tags and a time estimate:

```bash
scripts/run_llm_jev.sh small --dry-run   # preview, ~1 h run
scripts/run_llm_jev.sh small             # 12-sample ladder on one dataset
scripts/run_llm_jev.sh all --limit 20    # every dataset, ~12 h
```

Each step streams its own output as `[<step>] ...` lines, and the run ends
with a `===== RESULT =====` block: one line per row (TP/FP/FN/TN, P, R, F1,
elapsed time), the model, the endpoint probe and `failures=<n>`. **Copy-paste
that block back** — analysis needs only it, not a re-run.

Equivalent one-leg form, if you want to run a single experiment by hand (every
command reads `.env` / the environment, so override only what differs):

```bash
# A — static tools only (no LLM)
SCENARIO_PHASE3_MODE=phase1 SCENARIO_PHASE3_DATASET=datasets/vulnllm_r_c.json \
SCENARIO_PHASE3_OUTPUT=results/exp_vulnllm_r_c_static.json \
python codey_security.py phase3

# B — LLM only: one full source file, no static evidence
python scripts/run_llm_only_benchmark.py \
  --dataset datasets/llm_subset_20.json --out results/exp_B_llm_only.jsonl \
  --concurrency 8 --resume
python scripts/evaluate_llm_only.py \
  --dataset datasets/llm_subset_20.json --predictions results/exp_B_llm_only.jsonl \
  --out results/exp_B_llm_only.json

# C — static findings + LLM, no structural evidence (ablation)
PHASE2_INCLUDE_STRUCTURAL=false SCENARIO_PHASE3_MODE=phase2 \
SCENARIO_PHASE3_DATASET=datasets/llm_subset_20.json \
SCENARIO_PHASE3_LABEL=static_llm SCENARIO_PHASE3_OUTPUT=results/exp_C_static_llm.json \
python codey_security.py phase3

# D — static + structural evidence + LLM (proposed system)
PHASE2_INCLUDE_STRUCTURAL=true SCENARIO_PHASE3_MODE=phase2 \
SCENARIO_PHASE3_DATASET=datasets/llm_subset_20.json \
SCENARIO_PHASE3_LABEL=static_structural_llm SCENARIO_PHASE3_OUTPUT=results/exp_D_full.json \
python codey_security.py phase3
```

Experiment B appends one JSON line per sample as it finishes, so `--resume`
after an interruption; `evaluate_llm_only.py` reports samples that never got a
record instead of silently dropping them.

Compare the four:

```bash
python scripts/aggregate_phase3.py results/exp_A_static.json \
  results/exp_B_llm_only.json results/exp_C_static_llm.json \
  results/exp_D_full.json --csv results/comparison.csv
```

Each result file carries `metadata.provenance`: dataset, model, base URL,
structural-evidence switch, line tolerance, tool versions, elapsed time and
the finish timestamp.

---

## Benchmark datasets

All manifests live in `datasets/` in the same labelled schema
(`dataset_schema.json`): `sample_id`, `vulnerable`, `cwe[]`, `file`, plus a
`source` path and `language`.

| Manifest | Language | Population | Used for |
|---|---|---|---|
| `vulnllm_r_c.json` | C | VulnLLM-R C functions, vulnerable + benign | A, E |
| `vulnllm_r_c_dataflow.json` | C | VulnLLM-R C with dataflow annotations | default LLM subset source |
| `vulnllm_r_python.json` | Python | VulnLLM-R Python functions | A, E, LLM subset via `--llm-source` |
| `vulnllm_r_repo_c.json` | C | VulnLLM-R repository-level C | A |
| `python_bench/python_bench.json` | Python | six studied classes (synthetic) | regression harness |
| `proposal_min10.json` | C + Python | 8–10 samples per class | proposal-aligned smoke set |
| `primevul_test_paired.json` | C | PrimeVul test pairs | A, E |
| `bigvul_test.json` | C | Big-Vul test split | A, E |

`python scripts/run_benchmarks.py --list` prints sample/vulnerable counts and
languages for each of them. Do not hand-write ground-truth entries: add a new
corpus through `scripts/make_manifest.py` (SARD / Devign / Big-Vul importers)
and then manually audit a small validation subset before using its numbers.

---

## Development

```bash
pytest -q
```

For research runs:

1. Pin Python and package versions.
2. Record the exact scanner versions.
3. Record the LLM/model name.
4. Use deterministic temperature settings for evaluation.
5. Save raw Phase 1 and Phase 2 reports.
6. Never tune the matcher on the test set.
7. Keep benchmark splits fixed across experiments.
8. Report failures and skipped samples rather than silently dropping them.
9. In deterministic evidence runs, a failed Bandit or Flawfinder scan excludes
   that sample from the baseline and union tallies and is reported as an
   unavailable baseline sample; it is not scored as a negative.

---

## Current limitations

- Clang Static Analyzer is not integrated into Phase 1 (it needs
  `compile_commands.json` to be comparable with the pattern-based tools).
- The principal manifests (VulnLLM-R, PrimeVul, Big-Vul) carry weak labels
  inherited from their source corpora (patched-commit and function-level
  heuristics), so a manually audited validation subset is still required before
  any published claim.
- The example manifest (`datasets/manifest.example.json`) is only a smoke
  test; it is not a research benchmark.
- The taint tracker is intra-procedural. It recovers assignment-level
  propagation and C parameter/global origins, but not inter-procedural flows, so
  a bug whose source and sink are in different functions is out of its reach.
- Taint recall is low by construction on overflow-style bugs. On the historical
  600-sample Juliet subset (shipped as `results/exp_E_taint_evidence.json`)
  counting any source-to-sink path gave TP 26 / FP 33 over
  600 samples (recall `0.087`, benign flag rate `0.110`); counting only
  unmitigated paths, TP 7 / FP 7 (recall `0.023`, benign flag rate `0.023`).
  Low recall is expected, because the CWE-122 and CWE-190 test cases are size-
  and allocation-mismatches rather than data flows. This is a property of the
  benchmark, not a defect to be tuned away, and it is why taint evidence is
  used to verify injection findings rather than to detect overflow.
- The evaluator records `per_language` and
  `languages_without_evidence_support` for this reason. A language with no
  taint pattern table produces no chains at all, which would otherwise be
  indistinguishable from "found nothing" once folded into the totals: C++ was
  silently scored as safe until `cpp` was mapped onto the C patterns.
- The Python benchmark (`datasets/python_bench/`) is synthetic and was written
  alongside the detector. It is a regression harness for the six studied
  classes, not an independent evaluation set.
- SARD and Big-Vul loaders exist (`scripts/make_manifest.py`) but no numbers
  from them are reported. SARD's authoritative archives and the `benjio/bigvul`
  repository now both return 404, and the third-party mirrors that do exist
  cannot be checked against a source of record, so a precision or recall taken
  from one would be measuring a corpus whose labels are unverified. That is not
  worth a row in the results table.

### Devign (independent evidence)

The Devign corpus (27,318 labelled C functions from qemu and FFmpeg, from
`epicosy/devign`) is one independent corpus evaluated so far. It is real
project code rather than template variants, so it does not share the blind
spot of template-generated benchmarks.

| Set | Metric | TP | FP | FN | TN | Precision | Recall | Benign flag rate |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 27,258 functions | any source-to-sink path | 971 | 894 | 11454 | 13939 | 0.521 | 0.078 | 0.060 |
| 27,258 functions | unmitigated path only | 861 | 783 | 11564 | 14050 | 0.524 | 0.069 | 0.053 |
| stratified 600 | unmitigated path only | 17 | 21 | 283 | 279 | 0.447 | 0.057 | 0.070 |
| stratified 600 | Flawfinder | 6 | 11 | 294 | 289 | 0.353 | 0.020 | 0.037 |
| stratified 600 | union | 20 | 29 | 280 | 271 | 0.408 | 0.067 | 0.097 |

Results are in `results/exp_G_devign_taint_full.json` and
`results/exp_G_devign_taint_strat600.json`. The `dataset` field inside them
records the transient path the run was made from; to reproduce, fetch
`data/raw/dataset.json` from `epicosy/devign` and run:

```bash
python scripts/make_manifest.py devign --input <dataset.json> \
  --out /tmp/devign/devign_manifest.json
python scripts/eval_taint_evidence.py --dataset /tmp/devign/devign_manifest.json \
  --out results/exp_G_devign_taint_full.json
```

Recall is low for a reason worth stating plainly: Devign's label means "this
function was touched by a security fix", which covers far more than the narrow
set of flows the taint engine models. The precision and benign flag rate are the
meaningful figures here, and on equal footing the taint evidence carries about
2.8x Flawfinder's recall at higher precision — while costing no model calls.

Devign's functions also carry label-revealing comments (16 of 27,258 mention a
CVE id or "exploit"). All 27,258 were run through `phase2.sanitize` and 0
markers survived, so the corpus is usable for the LLM phases as well.
- Phase 2 has been wired and tested end to end with a stub agent. Runs against
  the live endpoint are in progress and are still erroring often enough that
  the provider is the limiting factor on the LLM-based experiments.
- The full Experiment B run timed out on 1,068 of its requests at 180s, and
  failed to parse 6 more responses. A timed-out sample is scored as a
  non-detection, so the B recall figure is a **lower bound** on what the model
  would achieve on a healthy endpoint, and its precision is pessimistic in the
  same way. This is a property of the run, not of the method, and is the reason
  the deterministic evidence results above are the more trustworthy measurement.


---

## Roadmap

### Completed

- [x] Tree-sitter structural extraction
- [x] Python/C/C++ language routing
- [x] Bandit integration
- [x] Cppcheck integration
- [x] Flawfinder integration
- [x] Normalized finding schema
- [x] Deduplication and function-scope correlation
- [x] Evidence-aware Security Agent over LLM (single-agent baseline)
- [x] Source-to-sink taint chain recovery with sanitizer and mitigation rules
- [x] Scanner Agent / Verifier Agent orchestration with a code-level evidence gate
- [x] NVD-verified CWE/CVE catalogue feeding the report's reference fields
- [x] Python benchmark across the six studied classes
- [x] Head-to-head evaluation against Flawfinder and Bandit
- [x] Ground-truth dataset schema
- [x] Finding matcher with component-aware file matching
- [x] Precision/Recall/F1/FPR evaluation
- [x] Per-CWE reporting
- [x] Multi-experiment aggregation
- [x] Select-driven benchmark runner (`scripts/run_benchmarks.py`: suites,
      legs, datasets, `--list` / `--dry-run`, per-language taint baseline)
- [x] VulnLLM-R / PrimeVul / Big-Vul / Python benchmark manifests
- [x] Large-scale benchmark runner (dedicated Phase-1 pool, async LLM fan-out)
- [x] Label-leak sanitization of every LLM-visible string
- [x] Run provenance recording (model, tool versions, settings, elapsed time)
- [x] Ablation switches for structural, taint and tool evidence
- [x] SARD / Devign / Big-Vul manifest loaders
- [x] Devign measured on all 27,258 functions plus a Flawfinder comparison

### Next

- [ ] Inter-procedural taint propagation
- [ ] Measure SARD or Big-Vul as well, if a source of record for their labels
      can be found, so the independent evidence spans more than one corpus
- [ ] Live multi-agent runs on both the C and Python benchmarks
- [ ] Results visualization for thesis/paper

---

## Citation / research use

When writing the thesis, document the exact analyzer versions, model versions,
benchmark split, matching policy, and agent prompt used for each experiment.
