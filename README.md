# Codey Security

**Evidence-driven multi-agent vulnerability analysis for Python and C/C++.**

Codey Security combines deterministic program analysis with LLM-based security reasoning and empirical evaluation. The project is organized into three completed development phases:

1. **Phase 1 — Structural + Static Analysis**: parse source code with Tree-sitter and normalize findings from Bandit, Cppcheck, Flawfinder, and Clang Static Analyzer.
2. **Phase 2 — Evidence-Aware Multi-Agent Reasoning**: have specialized agents independently inspect the evidence, challenge each other, and produce a final `CONFIRMED / REJECTED / UNCERTAIN` decision.
3. **Phase 3 — Benchmark + Evaluation**: compare predictions against ground truth and calculate Precision, Recall, F1, FPR, specificity, accuracy, and per-CWE results.

> **Repository status:** Research prototype, active development. The bundle is the consolidated Phase 1–3 research core produced in this conversation. It is not a byte-for-byte copy of the latest GitHub repository because the execution environment could not reach GitHub while this bundle was assembled. Preserve your existing application/UI files from your GitHub checkout when merging this research core.

---

## Research objective

The project is designed around the following research question:

> **Can deterministic structural/static evidence combined with multi-agent LLM verification reduce false positives in source-code vulnerability detection compared with static analysis or LLM-only approaches?**

The architecture intentionally separates evidence generation from LLM judgment. This makes it possible to run controlled baselines and ablation experiments instead of only reporting qualitative examples.

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
                    │ Security Agent          │
                    │ Context Agent           │
                    │ Adversarial Critic      │
                    │ Final Adjudicator       │
                    └────────────┬───────────┘
                                 │
                    CONFIRMED / REJECTED /
                           UNCERTAIN
                                 │
                           Phase 3 ▼
                    ┌────────────────────────┐
                    │ Ground truth benchmark │
                    │ Finding matcher        │
                    │ Precision / Recall/F1  │
                    │ FPR / specificity      │
                    │ Per-CWE analysis       │
                    │ Experiment comparison  │
                    └────────────────────────┘
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the detailed component and data-flow design.

---

## Project structure

```text
codey-security/
├── analyzers/                      # Phase 1 deterministic analysis
│   ├── finding.py                  # canonical finding model
│   ├── structural_analyzer.py      # Tree-sitter AST/structure extraction
│   ├── static_tools.py             # Bandit/Cppcheck/Flawfinder/Clang adapters
│   └── phase1_pipeline.py          # unified Phase 1 pipeline
│
├── phase2/                         # Phase 2 multi-agent reasoning
│   ├── models.py
│   ├── prompts.py
│   ├── context.py
│   ├── llm.py                      # bridge to existing agent/LLM stack
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
├── examples/                       # small sanity-check samples
├── datasets/                       # benchmark manifests / Juliet integration area
├── configs/                        # configuration templates
├── results/                        # generated reports (gitignored)
├── scripts/                        # developer/diagnostic helpers
├── tests/                          # unit + integration tests
├── docs/                           # architecture, research plan, dataset notes
├── run_phase2.py
├── run_phase3.py
├── aggregate_phase3.py
├── run_pipeline.py                 # unified CLI
├── dataset_schema.json
├── requirements.txt
├── requirements-dev.txt
├── pyproject.toml
├── Makefile
├── .env.example
├── .gitignore
└── README.md
```

---

## Supported languages

| Language | Structural analysis | Security/static baseline |
|---|---|---|
| Python | Tree-sitter | Bandit |
| C | Tree-sitter | Cppcheck, Flawfinder, Clang Static Analyzer |
| C++ | Tree-sitter | Cppcheck, Flawfinder, Clang Static Analyzer |

The C/C++ Clang integration is intentionally conservative in standalone-file mode. For real repositories with build systems, Phase 1 should eventually consume `compile_commands.json` or the project's actual build command.

---

## Installation

### 1. System packages

Ubuntu/Debian example:

```bash
sudo apt update
sudo apt install -y python3 python3-venv cppcheck flawfinder clang clang-tools
```

Verify the external tools:

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
pip install -r requirements-dev.txt
```

### 3. Existing LLM/AutoGen integration

Phase 2 deliberately reuses the project's existing agent abstraction. When running Phase 2 from your original GitHub checkout, make sure the existing `agents/` and `config/` packages remain present.

Copy `.env.example` to `.env` and configure the provider used by your existing application.

---

## Quick start

### Phase 1: analyze one file

```bash
python run_pipeline.py phase1 examples/cpp/vulnerable.cpp --out results/phase1.json
```

Python:

```bash
python run_pipeline.py phase1 examples/python/vulnerable.py --out results/phase1-python.json
```

Or directly:

```bash
python -m analyzers.phase1_pipeline examples/cpp/vulnerable.cpp --out results/phase1.json
```

### Phase 2: evidence-aware multi-agent verification

```bash
python run_phase2.py results/phase1.json \
  --provider ollama \
  --out results/phase2.json
```

For OpenAI:

```bash
python run_phase2.py results/phase1.json \
  --provider openai \
  --out results/phase2.json
```

### Phase 3: benchmark evaluation

Create a ground-truth manifest following `dataset_schema.json`, then run:

```bash
python run_phase3.py datasets/manifest.json \
  --mode phase1 \
  --out results/phase1-evaluation.json
```

For Phase 2:

```bash
python run_phase3.py datasets/manifest.json \
  --mode phase2 \
  --provider ollama \
  --out results/phase2-evaluation.json
```

Compare experiments:

```bash
python aggregate_phase3.py \
  results/phase1-evaluation.json \
  results/phase2-evaluation.json \
  --csv results/comparison.csv
```

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
    }
  }
}
```

This format is the contract consumed by Phase 2.

---

## Phase 2 decision model

Every correlated finding is processed by independent evidence-oriented roles:

- **Security agent:** determine whether the observed operation is security-relevant.
- **Context agent:** inspect local source context and structural information.
- **Adversarial critic:** look specifically for reasons the warning could be a false positive.
- **Final adjudicator:** combine evidence and return one of:
  - `CONFIRMED`
  - `REJECTED`
  - `UNCERTAIN`

`UNCERTAIN` is intentional. The system should not invent certainty when the evidence is insufficient.

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

The implementation also reports specificity, false-negative rate, accuracy, balanced accuracy, positive/negative support, and per-CWE results.

**Important:** TP/FP/FN are finding-level quantities, while TN requires an explicit benign/negative sample population. Do not report a single FPR from a vulnerable-only dataset.

---

## Recommended research experiments

The project is structured to support these experiments:

| Experiment | Evidence | LLM reasoning | Purpose |
|---|---|---|---|
| A | Static tools | No | baseline |
| B | Source code | LLM only | LLM baseline |
| C | Static findings | Yes | static + LLM |
| D | AST + static findings | Yes | structural/context contribution |
| E | AST + static + critic/adjudicator | Yes | proposed system |

For each experiment report:

- Precision
- Recall
- F1
- False Positive Rate
- Runtime
- LLM/token cost, when available
- per-CWE breakdown

Use the same benchmark split for every experiment.

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

Do not hand-write hundreds of ground-truth entries. Build a deterministic manifest generator from Juliet's directory/file naming conventions and then manually audit a small validation subset.

See [`docs/DATASET_AND_EVALUATION.md`](docs/DATASET_AND_EVALUATION.md).

---

## Development

Run tests:

```bash
pytest -q
```

Run static checks:

```bash
python scripts/doctor.py
```

Useful Make targets:

```bash
make test
make doctor
make phase1 FILE=examples/cpp/vulnerable.cpp
```

---

## Reproducibility principles

For research runs:

1. Pin Python and package versions.
2. Record the exact scanner versions.
3. Record the LLM/provider/model name.
4. Use deterministic temperature settings for evaluation where possible.
5. Save raw Phase 1 and Phase 2 reports.
6. Never tune the matcher on the test set.
7. Keep benchmark splits fixed across experiments.
8. Report failures and skipped samples rather than silently dropping them.

---

## Current limitations

- Phase 1 standalone Clang analysis is not yet build-system aware.
- Phase 2 depends on the existing AutoGen/agent implementation in your original repository.
- The Phase 3 example dataset is only a smoke test; it is not a research benchmark.
- Juliet ground-truth generation is the next major experiment-specific task.
- Function-level data-flow/taint analysis is not yet implemented; the current Tree-sitter layer is primarily structural.

These limitations are intentional boundaries for the Phase 1–3 milestone.

---

## Roadmap

### Completed in this consolidated research core

- [x] Tree-sitter structural extraction
- [x] Python/C/C++ language routing
- [x] Bandit integration
- [x] Cppcheck integration
- [x] Flawfinder integration
- [x] Clang Static Analyzer integration
- [x] Normalized finding schema
- [x] Deduplication/correlation
- [x] Evidence-aware multi-agent reasoning
- [x] Adversarial critic
- [x] Final adjudication
- [x] Ground-truth dataset schema
- [x] Finding matcher
- [x] Precision/Recall/F1/FPR evaluation
- [x] Per-CWE reporting
- [x] Multi-experiment aggregation

### Next

- [ ] Juliet 1.3 manifest generator
- [ ] Large-scale benchmark runner
- [ ] Ablation runner with fixed seeds/settings
- [ ] Compile-commands-aware C/C++ analysis
- [ ] Stronger data-flow/taint evidence
- [ ] Results visualization for thesis/paper

---

## Citation / research use

This repository is organized so that the implementation can be described as an evidence-first security analysis pipeline rather than a generic multi-agent chatbot. When writing the thesis, document the exact analyzer versions, model versions, benchmark split, matching policy, and agent prompts used for each experiment.

---

# Juliet C/C++ 1.3 benchmark

Codey Security includes a dedicated Juliet ingestion and baseline runner for the next research stage.

Juliet C/C++ 1.3 is a NIST Software Assurance Reference Dataset from the NSA Center for Assured Software. NIST reports 64,099 test cases organized across 118 CWEs. The suite distinguishes intentionally buggy (`bad`) and bug-free (`good`) test cases, which makes it suitable for controlled detector evaluation. 

## 1. Obtain Juliet

Use the official NIST distribution or a repository containing the unmodified Juliet C/C++ 1.3 testcases. One convenient Unix-oriented mirror is `arichardson/juliet-test-suite-c`, whose repository documents that it contains Juliet 1.3 and organizes test cases below `testcases/`.

For example:

```bash
git clone https://github.com/arichardson/juliet-test-suite-c.git external/juliet-test-suite-c
```

For research reporting, record the exact Juliet version, source, checksum, and commit/archive used. NIST publishes the official SHA-256 for the 1.3 package.

## 2. Generate a manifest

Start with a small subset while validating the pipeline:

```bash
python scripts/generate_juliet_manifest.py \
    external/juliet-test-suite-c \
    --cwe CWE-120 \
    --max-samples 100 \
    --out datasets/juliet_1.3_cwe120.json
```

Generate a complete manifest later:

```bash
python scripts/generate_juliet_manifest.py \
    external/juliet-test-suite-c \
    --out datasets/juliet_1.3_manifest.json
```

The generator classifies a Juliet source file conservatively from its filename:

```text
*_bad*.c / *.cpp  -> vulnerable=true
*_good*.c / *.cpp -> vulnerable=false
```

It also records:

- CWE identifier
- language
- Juliet scenario/group ID
- vulnerable/benign variant
- bad/good function when detectable
- source line of that function when detectable

## 3. Create group-safe splits

Do not randomly split individual Juliet files when good/bad variants belong to the same scenario. Keep all variants from one `group_id` in the same split to reduce leakage.

```bash
python scripts/split_juliet_manifest.py \
    datasets/juliet_1.3_manifest.json \
    --train-out datasets/juliet_1.3_train.json \
    --test-out datasets/juliet_1.3_test.json \
    --test-ratio 0.2 \
    --seed 42
```

## 4. Run the static-analysis baseline

```bash
python scripts/run_juliet_benchmark.py \
    datasets/juliet_1.3_test.json \
    --out results/juliet_phase1.json
```

During early debugging it can be useful to disable Clang Static Analyzer:

```bash
python scripts/run_juliet_benchmark.py \
    datasets/juliet_1.3_test.json \
    --no-clang \
    --out results/juliet_phase1_no_clang.json
```

The runner stores both benchmark results and per-sample Phase 1 reports. This allows later auditing of every FP/FN instead of reporting only aggregate numbers.

## 5. Experimental protocol

The first controlled experiments should be:

```text
E1  Cppcheck / Flawfinder / Clang baseline
E2  Phase 1 normalized static baseline
E3  Phase 2 multi-agent verification
E4  Phase 2 without critic (ablation)
E5  Phase 2 without structural context (ablation)
E6  Full proposed system
```

For every experiment record:

```text
TP, FP, FN, TN
Precision, Recall, F1
False Positive Rate
Specificity
Accuracy
Balanced Accuracy
per-CWE metrics
runtime
number of findings
```

Do not tune prompts or thresholds on the held-out Juliet test split. Use the training/development split for system tuning, then freeze the configuration before evaluating the test split.

## 6. Juliet-specific ground-truth caveat

The generated manifest is deliberately a **file/sample-level ground truth**, not a claim that every line of a `bad` file is vulnerable. Juliet's documentation describes a structured test-case design in which each case contains a buggy code path and similar bug-free code; some cases span multiple files. For this reason, the initial matcher emphasizes file + CWE, with line/function information used as supporting evidence when available.

For multi-file cases, the next refinement should introduce a Juliet case-level grouping model so a single logical vulnerability can span several source files without being counted multiple times.
