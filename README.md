# Codey Security

**Evidence-driven vulnerability analysis for Python and C/C++.**

Codey Security combines deterministic program analysis with LLM-based security
reasoning and empirical evaluation. The project is organized into three
completed development phases:

1. **Phase 1 — Structural + Static Analysis**: parse source code with
   Tree-sitter and normalize findings from Bandit, Cppcheck, Flawfinder, and
   Clang Static Analyzer.
2. **Phase 2 — Evidence-Aware Security Verification**: a single Security Agent
   (an LLM session) reviews each correlated Phase 1 finding together with
   structural evidence and source context and returns
   `CONFIRMED / REJECTED / UNCERTAIN`.
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
                                 │
                                 ▼
                       Clang Static Analyzer
                                 │
                                 ▼
                    ┌────────────────────────┐
                    │ Finding normalization   │
                    │ + deduplication         │
                    │ + correlation           │
                    └────────────┬───────────┘
                                 │
                            Phase 2 ▼
                     ┌────────────────────────┐
                     │ Security Agent         │
                     │ (OpenCode session API) │
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

Phase 2 is intentionally a single agent. The research question is whether
**evidence quality** (structural + static analysis) improves an LLM's ability
to make a defensible finding-level judgement, not whether multiple LLMs can
outvote each other. A future multi-agent variant (Context Agent, Adversarial
Critic, Final Adjudicator) can be layered on top of the same Phase 1 evidence
packet if that becomes a separate research direction.

---

## Project structure

```text
codey-security/
├── analyzers/                      # Phase 1 deterministic analysis
│   ├── finding.py                  # canonical finding model + correlation
│   ├── structural_analyzer.py      # Tree-sitter AST/structure extraction
│   ├── static_tools.py             # Bandit/Cppcheck/Flawfinder/Clang adapters
│   └── phase1_pipeline.py          # unified Phase 1 pipeline
│
├── agents/                         # LLM agents
│   └── security_agent.py           # single LLM Security Agent
│
├── phase2/                         # Phase 2 orchestration
│   ├── models.py
│   ├── prompts.py                  # reference prompt text
│   ├── context.py                  # sanitized source window for the agent
│   ├── sanitize.py                 # removes Juliet label leaks
│   ├── llm.py
│   └── pipeline.py
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
│   ├── generate_juliet_manifest.py # Juliet 1.3 manifest generator
│   ├── import_hf_juliet.py         # Hugging Face Juliet import
│   ├── split_juliet_manifest.py    # group-aware train/test split
│   ├── run_juliet_benchmark.py     # experiment A (static tools only)
│   ├── run_llm_only_benchmark.py   # experiment B (LLM only)
│   └── evaluate_llm_only.py        # score experiment B with the shared matcher
│
├── examples/                       # small sanity-check samples
├── datasets/                       # benchmark manifests / Juliet integration
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
| C | Tree-sitter | Cppcheck, Flawfinder, Clang Static Analyzer |
| C++ | Tree-sitter | Cppcheck, Flawfinder, Clang Static Analyzer |

Clang integration is intentionally conservative in standalone-file mode. For
real repositories with build systems, Phase 1 should consume
`compile_commands.json` or the project's actual build command.

---

## Installation

### 1. System packages

Ubuntu/Debian example:

```bash
sudo apt update
sudo apt install -y python3 python3-venv cppcheck flawfinder clang clang-tools
```

Verify:

```bash
cppcheck --version
flawfinder --version
scan-build --version
clang --version
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
opencode serve --port 4096 --hostname 127.0.0.1
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
python codey_security.py phase2   # Phase 1 + Security Agent verification
python codey_security.py phase3   # benchmark against a ground-truth dataset
python codey_security.py full     # Phase 1 -> Phase 2 -> Phase 3
```

There are intentionally no `--provider`, `--out`, `--dataset` or `--mode`
flags. See `README_CLI_CONFIG.md`.

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

Each correlated Phase 1 group is sent to a single **Security Agent**. The
agent receives:

- the normalized finding group (tools, CWEs, messages, fingerprints),
- the structural metadata from Phase 1 (functions, calls, branches),
- a configurable window of source lines around the finding.

The agent returns exactly one of:

- `CONFIRMED` — supplied evidence is sufficient to support the finding.
- `REJECTED` — supplied evidence contradicts the finding or shows it benign.
- `UNCERTAIN` — evidence is insufficient for either conclusion.

`UNCERTAIN` is intentional. The system should not invent certainty when the
evidence is insufficient. Every response also carries a confidence score, a
short technical rationale, explicit supporting evidence, and a list of missing
evidence items so the decision can be audited.

Phase 2 is powered by an OpenCode session (`LLM_BASE_URL`, `LLM_MODEL_ID`,
`LLM_PROVIDER_ID`). The model is recorded in every Phase 3 result under
`metadata.provenance`.

Before any text reaches the model, `phase2/sanitize.py` removes label leaks
from the evidence packet: Juliet comments (`CWE: 190`, `POTENTIAL FLAW`) are
blanked in place so line numbers stay valid, and scenario identifiers such as
`CWE190_Integer_Overflow__int_45_bad`, `badSink` and `goodG2B` are rewritten
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

Every command reads its settings from `.env` / the environment, so override
only what differs per experiment. Use one dataset for all four runs.

```bash
# A — static tools only (no LLM)
SCENARIO_PHASE3_MODE=phase1 SCENARIO_PHASE3_DATASET=datasets/juliet_test.json \
SCENARIO_PHASE3_OUTPUT=results/exp_A_static.json \
python codey_security.py phase3

# B — LLM only: one full source file, no static evidence
python scripts/run_llm_only_benchmark.py \
  --dataset datasets/juliet_test.json --out results/exp_B_llm_only.jsonl \
  --concurrency 8 --resume
python scripts/evaluate_llm_only.py \
  --dataset datasets/juliet_test.json --predictions results/exp_B_llm_only.jsonl \
  --out results/exp_B_llm_only.json

# C — static findings + LLM, no structural evidence (ablation)
PHASE2_INCLUDE_STRUCTURAL=false SCENARIO_PHASE3_MODE=phase2 \
SCENARIO_PHASE3_DATASET=datasets/juliet_test.json \
SCENARIO_PHASE3_LABEL=static_llm SCENARIO_PHASE3_OUTPUT=results/exp_C_static_llm.json \
python codey_security.py phase3

# D — static + structural evidence + LLM (proposed system)
PHASE2_INCLUDE_STRUCTURAL=true SCENARIO_PHASE3_MODE=phase2 \
SCENARIO_PHASE3_DATASET=datasets/juliet_test.json \
SCENARIO_PHASE3_LABEL=static_structural_llm SCENARIO_PHASE3_OUTPUT=results/exp_D_full.json \
python codey_security.py phase3
```

Experiment B appends one JSON line per sample as it finishes, so `--resume`
after an interruption; `evaluate_llm_only.py` reports samples that never got a
record instead of silently dropping them.

Compare the four:

```bash
python aggregate_phase3.py results/exp_A_static.json results/exp_B_llm_only.json \
  results/exp_C_static_llm.json results/exp_D_full.json --csv results/comparison.csv
```

Each result file carries `metadata.provenance`: dataset, model, base URL,
structural-evidence switch, line tolerance, tool versions, elapsed time and
the finish timestamp.

---

## Juliet integration plan

The intended research benchmark is **Juliet Test Suite for C/C++ 1.3**.

Recommended layout:

```text
datasets/
└── juliet/
    ├── manifest.json
    └── samples/...
```

Do not hand-write hundreds of ground-truth entries. Build a deterministic
manifest generator from Juliet's directory/file naming conventions and then
manually audit a small validation subset.

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

---

## Current limitations

- Phase 1 standalone Clang analysis is not yet build-system aware.
- Juliet labels are derived from the `bad`/`good` naming convention; a manually
  audited validation subset is still required before any published claim.
- The example manifest (`datasets/manifest.example.json`) is only a smoke
  test; it is not a research benchmark.
- Function-level data-flow/taint analysis is not yet implemented; the current
  Tree-sitter layer is primarily structural.
- Phase 2 is a single agent. Multi-agent verification (context agent,
  adversarial critic, final adjudicator) is a documented future direction,
  not part of the current research core.

---

## Roadmap

### Completed

- [x] Tree-sitter structural extraction
- [x] Python/C/C++ language routing
- [x] Bandit integration
- [x] Cppcheck integration
- [x] Flawfinder integration
- [x] Clang Static Analyzer integration
- [x] Normalized finding schema
- [x] Deduplication and function-scope correlation
- [x] Evidence-aware Security Agent over LLM
- [x] Ground-truth dataset schema
- [x] Finding matcher with component-aware file matching
- [x] Precision/Recall/F1/FPR evaluation
- [x] Per-CWE reporting
- [x] Multi-experiment aggregation
- [x] Juliet 1.3 manifest generator + group-aware train/test split
- [x] Large-scale benchmark runner (dedicated Phase-1 pool, async LLM fan-out)
- [x] Label-leak sanitization of every LLM-visible string
- [x] Run provenance recording (model, tool versions, settings, elapsed time)
- [x] Ablation switch for structural evidence (`PHASE2_INCLUDE_STRUCTURAL`)

### Next

- [ ] Reproducible one-command A–D sweep (the commands are documented, not scripted)
- [ ] Compile-commands-aware C/C++ analysis
- [ ] Stronger data-flow/taint evidence
- [ ] Results visualization for thesis/paper
- [ ] Optional multi-agent extension

---

## Citation / research use

When writing the thesis, document the exact analyzer versions, model versions,
benchmark split, matching policy, and agent prompt used for each experiment.
