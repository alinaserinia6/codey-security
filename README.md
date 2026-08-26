# Codey-Security

## Structural and Multi-Agent Code Vulnerability Assessment with False-Positive Reduction

Codey-Security is a research project for improving **Static Application Security Testing (SAST)** by combining deterministic program analysis with **Large Language Model (LLM) reasoning** and **multi-agent verification**.

The central research objective is to determine whether structural program information and specialized LLM agents can **reduce false-positive vulnerability reports while preserving useful vulnerability detection performance**.

The project targets **Python and C/C++ source code** and is designed as a reproducible research pipeline rather than only a standalone vulnerability scanner.

> **Project status:** Research prototype in active development. The Phase 1–3 architecture and evaluation framework are implemented in the accompanying research codebase; integration with the existing application/agent UI is ongoing.

---

## Table of Contents

- [Research Problem](#research-problem)
- [Research Question](#research-question)
- [Objectives](#objectives)
- [System Overview](#system-overview)
- [Architecture](#architecture)
- [Phase 1 — Deterministic Program Analysis](#phase-1--deterministic-program-analysis)
- [Phase 2 — Multi-Agent Vulnerability Verification](#phase-2--multi-agent-vulnerability-verification)
- [Phase 3 — Benchmarking and Evaluation](#phase-3--benchmarking-and-evaluation)
- [Finding Representation](#finding-representation)
- [Datasets](#datasets)
- [Experimental Design](#experimental-design)
- [Evaluation Metrics](#evaluation-metrics)
- [Target Vulnerability Classes](#target-vulnerability-classes)
- [Technology Stack](#technology-stack)
- [Repository Structure](#repository-structure)
- [Installation](#installation)
- [Usage](#usage)
- [Juliet Benchmark](#juliet-benchmark)
- [Research Reproducibility](#research-reproducibility)
- [Current Status](#current-status)
- [Limitations](#limitations)
- [Roadmap](#roadmap)
- [Research Contribution](#research-contribution)
- [References](#references)

---

## Research Problem

Traditional SAST tools are useful for identifying suspicious source-code constructs, but a static warning does not necessarily mean that a vulnerability is exploitable in its actual program context.

Typical sources of false positives include:

- a dangerous sink receiving a constant or trusted value;
- sanitization performed before the sink;
- source and sink being syntactically close but not connected by a real data flow;
- safe wrappers around otherwise dangerous APIs;
- interprocedural context that is unavailable to a simple pattern matcher;
- incomplete understanding of buffer sizes, constraints, or control flow.

At the same time, LLMs can reason about code context but may introduce their own problems, including hallucinated data flow, inconsistent judgments, and insufficient evidence.

Codey-Security therefore treats static analysis and LLM reasoning as **complementary sources of evidence**.

---

## Research Question

> **Can structural program analysis combined with specialized multi-agent LLM reasoning reduce false-positive vulnerability reports from static analysis while maintaining effective vulnerability detection?**

The project evaluates this question using controlled baselines, benchmark datasets, ground-truth labels, and ablation experiments.

---

## Objectives

The project has five primary objectives:

1. **Parse and structurally analyze source code** using language-aware program representations.
2. **Collect deterministic vulnerability evidence** from multiple static-analysis tools.
3. **Use specialized LLM agents to reason about and verify candidate findings.**
4. **Measure false-positive reduction quantitatively** against established baselines.
5. **Produce reproducible experiments** using benchmark datasets such as Juliet C/C++ 1.3.

---

# System Overview

The complete system is organized into three research phases:

```text
                         Source Code
                              │
                              ▼
                ┌──────────────────────────┐
                │ Phase 1                  │
                │ Structural + Static     │
                │ Program Analysis        │
                │                          │
                │ Tree-sitter              │
                │ Bandit                   │
                │ Cppcheck                 │
                │ Flawfinder               │
                │ Clang Static Analyzer    │
                └────────────┬─────────────┘
                             │
                             ▼
                    Normalized Findings
                             │
                             ▼
                ┌──────────────────────────┐
                │ Phase 2                  │
                │ Multi-Agent Reasoning    │
                │                          │
                │ Security Agent           │
                │ Context Agent            │
                │ Adversarial Critic       │
                │ Final Adjudicator        │
                └────────────┬─────────────┘
                             │
                             ▼
                  CONFIRMED / REJECTED /
                         UNCERTAIN
                             │
                             ▼
                ┌──────────────────────────┐
                │ Phase 3                  │
                │ Benchmark + Evaluation   │
                │                          │
                │ Ground Truth             │
                │ Finding Matching         │
                │ Precision / Recall       │
                │ F1 / FPR                 │
                │ Per-CWE Analysis         │
                └────────────┬─────────────┘
                             │
                             ▼
                    Experimental Results
```

The important design principle is that **Phase 1 provides deterministic evidence and Phase 2 interprets that evidence**. The LLM is not treated as the sole source of ground truth.

---

# Architecture

## Layer 1 — Structural Analysis

Tree-sitter is used to construct language-aware syntax information and extract structural features such as:

- functions and methods;
- function calls;
- imports/includes;
- control-flow-related constructs;
- source locations;
- suspicious API calls;
- parse errors;
- symbol and contextual information where available.

The structural representation gives later components more context than raw source text alone.

## Layer 2 — Static Analysis

Multiple deterministic tools can provide candidate findings:

| Language | Tool | Role |
|---|---|---|
| Python | Bandit | Python security baseline |
| C/C++ | Flawfinder | Dangerous-function and security-pattern baseline |
| C/C++ | Cppcheck | Static-analysis and defect/security findings |
| C/C++ | Clang Static Analyzer | Deeper semantic/static analysis |

The adapters normalize different scanner outputs into a common finding representation.

## Layer 3 — Finding Correlation

Different tools can report the same underlying vulnerability. The correlation layer therefore groups related findings using attributes such as:

- file;
- source location;
- function;
- CWE;
- rule identifier;
- normalized evidence.

This prevents the evaluation from incorrectly counting the same vulnerability multiple times.

## Layer 4 — Multi-Agent Reasoning

The normalized finding is passed to specialized agents. Each agent has a constrained responsibility rather than asking one LLM to perform the entire analysis.

## Layer 5 — Evaluation

The resulting decisions are matched against ground truth and evaluated using standard classification metrics.

---

# Phase 1 — Deterministic Program Analysis

Phase 1 creates the evidence that the multi-agent system will later reason about.

### Structural analysis

Supported source languages:

- Python
- C
- C++

The structural analyzer records information such as:

```json
{
  "language": "cpp",
  "functions": [],
  "calls": [],
  "imports": [],
  "dangerous_calls": [],
  "branch_count": 4,
  "node_count": 128,
  "parse_has_errors": false
}
```

### Static-analysis adapters

Each tool produces its native output, which is parsed into the common `Finding` model.

Conceptually:

```text
Bandit / Cppcheck / Flawfinder / Clang SA
                  │
                  ▼
          Tool-specific parser
                  │
                  ▼
          Normalized Finding
```

### Phase 1 design goal

Phase 1 should answer:

> **What deterministic evidence exists that this location may contain a vulnerability?**

It should not make the final exploitability judgment.

---

# Phase 2 — Multi-Agent Vulnerability Verification

Phase 2 takes the deterministic findings and performs structured reasoning.

## Security Evidence Agent

Examines the vulnerability class, dangerous operation, rule evidence, and security semantics.

## Program Context Agent

Examines surrounding source code and available structural information, including relevant callers/callees and source/sink context.

## Adversarial Critic

Attempts to disprove the finding by looking for:

- sanitization;
- validation;
- safe wrappers;
- constant or trusted inputs;
- unreachable paths;
- incorrect source/sink assumptions;
- insufficient evidence.

## Final Adjudicator

Combines the evidence and assigns one of three decisions:

```text
CONFIRMED
REJECTED
UNCERTAIN
```

`UNCERTAIN` is intentional. The system must not be forced to hallucinate certainty when the available evidence is insufficient.

### Agent output

A finding should contain structured evidence rather than only natural-language reasoning:

```json
{
  "decision": "CONFIRMED",
  "confidence": 0.91,
  "cwe": "CWE-120",
  "evidence": {
    "source": "user_input",
    "sink": "strcpy",
    "sanitizer": null,
    "call_chain": ["main", "process_input"]
  },
  "reason": "Unbounded input reaches a fixed-size destination without a validated length constraint."
}
```

---

# Phase 3 — Benchmarking and Evaluation

Phase 3 turns the scanner into a research experiment.

The evaluation pipeline is:

```text
Dataset
  │
  ├── Ground truth
  └── Source code
        │
        ▼
   Baseline tools
        │
        ├── Bandit
        ├── Flawfinder
        ├── Cppcheck
        └── Clang Static Analyzer
        │
        ▼
   Phase 1 findings
        │
        ▼
   Phase 2 decisions
        │
        ▼
 Ground-truth matching
        │
        ▼
   Evaluation metrics
```

The evaluation layer is designed so different experimental configurations can be compared using the same ground truth.

---

# Finding Representation

The project uses a normalized finding representation so all tools and agents can communicate through one schema.

A finding contains fields such as:

```json
{
  "id": "F-001",
  "tool": "cppcheck",
  "rule_id": "bufferAccessOutOfBounds",
  "message": "Potential buffer overflow",
  "file": "example.cpp",
  "line": 27,
  "column": 5,
  "severity": "HIGH",
  "cwe": ["CWE-120"],
  "evidence": "strcpy(buffer, input);",
  "confidence": 0.91,
  "status": "candidate"
}
```

After Phase 2, the finding additionally receives an adjudication result and supporting evidence.

---

# Datasets

## Primary benchmark — Juliet C/C++ 1.3

Juliet is the primary benchmark for the C/C++ evaluation because it contains labeled vulnerable and non-vulnerable test cases organized by CWE.

The repository contains a Juliet ingestion layer that can:

- parse Juliet test-case filenames;
- identify CWE identifiers;
- identify `good` and `bad` variants;
- preserve related scenario/group information;
- generate a normalized manifest;
- create group-safe train/test splits;
- run the benchmark through the evaluation pipeline.

The benchmark should initially be run on a controlled subset such as one or a small number of CWEs before scaling to the complete dataset.

## Other datasets / case studies

The research plan can additionally use:

- NIST SARD;
- Devign;
- Vul-Big;
- selected real-world CVE case studies.

These datasets serve different purposes and should not automatically be mixed into one metric table without documenting their different labeling and granularity assumptions.

---

# Experimental Design

The central experiment compares systems with progressively more information and reasoning.

## Baseline A — Static Analysis Only

```text
Static analyzer
      ↓
Final finding
```

## Baseline B — LLM Only

```text
Source code
    ↓
LLM
    ↓
Finding
```

## Experiment C — Static Analysis + LLM

```text
Static finding
     +
Source code
     ↓
LLM
     ↓
Decision
```

## Experiment D — Structural Analysis + Static Analysis + Multi-Agent Verification

```text
AST / structure
       +
Static findings
       +
Context
       ↓
Multi-agent verification
       ↓
Final decision
```

Experiment D is the main proposed system.

---

# Ablation Studies

To determine which components actually contribute to false-positive reduction, the project should run controlled ablations.

Recommended configurations:

| Configuration | Structural Analysis | Static Analysis | Multi-Agent Verification |
|---|---:|---:|---:|
| SAST | No | Yes | No |
| LLM | No | No | No |
| SAST + LLM | No | Yes | Yes (single verifier) |
| Structural + SAST | Yes | Yes | No |
| Proposed System | Yes | Yes | Yes |

Additional ablations can remove the critic, remove the context agent, or remove specific static analyzers.

The purpose is to establish whether improvements come from:

- more static-analysis coverage;
- structural context;
- LLM reasoning;
- multi-agent verification;
- or the interaction between these components.

---

# Evaluation Metrics

The primary metrics are:

### Precision

```text
Precision = TP / (TP + FP)
```

Measures how many reported findings are correct.

### Recall

```text
Recall = TP / (TP + FN)
```

Measures how many ground-truth vulnerabilities are detected.

### F1 Score

```text
F1 = 2 × Precision × Recall / (Precision + Recall)
```

### False Positive Rate

```text
FPR = FP / (FP + TN)
```

FPR is especially important for the project's main research objective: reducing false-positive findings.

### Specificity

```text
Specificity = TN / (TN + FP)
```

### Accuracy

```text
Accuracy = (TP + TN) / (TP + TN + FP + FN)
```

Accuracy should not be used as the only metric because class imbalance can make it misleading.

### Per-CWE Metrics

Results should also be reported separately by CWE so that improvements are not hidden by aggregate numbers.

---

# Target Vulnerability Classes

The project can evaluate vulnerability categories including:

- Buffer overflow
- Out-of-bounds access
- Command injection
- Code injection
- Template injection / SSTI
- Unsafe deserialization
- Integer overflow
- Dangerous API usage
- Other CWE categories supported by the benchmark

The initial real-world case studies from the proposal include:

| CVE | Project / Technology | Purpose |
|---|---|---|
| CVE-2021-3156 | Sudo | Real-world C case study |
| CVE-2017-7529 | Nginx | Real-world C case study |
| CVE-2021-25239 | Jinja/Flask ecosystem | Python case study |
| CVE-2022-22817 | PyYAML ecosystem | Python case study |

These CVEs should be treated as targeted case studies rather than as a substitute for a larger benchmark.

---

# Technology Stack

| Technology | Purpose |
|---|---|
| Python | Main implementation language |
| Tree-sitter | Parsing and structural analysis |
| Bandit | Python static-analysis baseline |
| Cppcheck | C/C++ static analysis |
| Flawfinder | C/C++ security-pattern baseline |
| Clang Static Analyzer | C/C++ semantic/static analysis |
| AutoGen | Multi-agent orchestration |
| LLM APIs / local LLMs | Code reasoning and verification |
| pytest | Unit and integration testing |
| JSON / CSV | Reproducible findings and evaluation results |
| Linux | Primary development/execution environment |

---

# Repository Structure

The recommended consolidated research structure is:

```text
codey-security/
│
├── analyzers/                       # Phase 1
│   ├── __init__.py
│   ├── finding.py                   # normalized finding model
│   ├── structural_analyzer.py       # Tree-sitter analysis
│   ├── static_tools.py              # scanner adapters
│   └── phase1_pipeline.py           # Phase 1 orchestration
│
├── phase2/                          # Phase 2
│   ├── __init__.py
│   ├── models.py                    # agent decision models
│   ├── prompts.py                   # agent prompts
│   ├── llm.py                       # model/provider adapter
│   ├── context.py                   # code-context extraction
│   └── pipeline.py                  # multi-agent verification
│
├── phase3/                          # Phase 3
│   ├── __init__.py
│   ├── metrics.py                   # evaluation metrics
│   ├── matcher.py                   # prediction/ground-truth matching
│   ├── models.py                    # evaluation data models
│   ├── dataset.py                   # dataset loading
│   └── juliet/
│       ├── parser.py                # Juliet metadata parser
│       ├── manifest.py              # manifest generation
│       └── split.py                 # group-safe splitting
│
├── datasets/                        # benchmark manifests
├── examples/                        # small reproducible examples
├── results/                         # experiment outputs
├── scripts/
│   ├── generate_juliet_manifest.py
│   ├── split_juliet_manifest.py
│   └── run_juliet_benchmark.py
├── tests/
│   ├── test_phase1.py
│   ├── test_phase2.py
│   ├── test_phase3.py
│   └── test_juliet.py
│
├── agents/                          # existing application/AutoGen layer
├── core/                            # existing application core
├── rules/                           # project-specific rules / cases
├── samples/                         # project samples
│
├── run_pipeline.py
├── run_phase2.py
├── run_phase3.py
├── aggregate_phase3.py
├── requirements.txt
├── requirements-dev.txt
├── requirements-system.txt
├── pyproject.toml
├── .env.example
├── .gitignore
└── README.md
```

The repository may contain additional application/UI files. The structure above identifies the research-critical components.

---

# Installation

## Python environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

## System tools

On Ubuntu/Debian, install the external C/C++ analyzers used by Phase 1:

```bash
sudo apt update
sudo apt install -y cppcheck flawfinder clang-tools
```

Verify:

```bash
cppcheck --version
flawfinder --version
scan-build --version
```

The exact `scan-build` executable name can vary with the installed Clang package/version.

---

# Usage

## Phase 1 — Analyze one file

```bash
python run_pipeline.py samples/example.cpp --out results/example.phase1.json
```

For Python:

```bash
python run_pipeline.py samples/example.py --out results/example.phase1.json
```

For a directory:

```bash
python run_pipeline.py ./samples --out results/samples.phase1.json
```

## Phase 2 — Multi-agent verification

```bash
python run_phase2.py samples/example.cpp \
    --provider ollama \
    --out results/example.phase2.json
```

For an API-based provider, configure the corresponding environment variables and use the project provider option.

## Phase 3 — Evaluation

```bash
python run_phase3.py datasets/manifest.json \
    --mode phase1 \
    --out results/phase1_eval.json
```

For the full Phase 1 + Phase 2 system:

```bash
python run_phase3.py datasets/manifest.json \
    --mode phase2 \
    --provider ollama \
    --out results/phase2_eval.json
```

Compare experiments:

```bash
python aggregate_phase3.py \
    results/phase1_eval.json \
    results/phase2_eval.json \
    --csv results/comparison.csv
```

---

# Juliet Benchmark

The Juliet integration is intended to make the benchmark reproducible.

Obtain a local Juliet C/C++ 1.3 checkout and point the scripts to its root.

Generate a controlled CWE subset:

```bash
python scripts/generate_juliet_manifest.py \
    /path/to/juliet-test-suite-c \
    --cwe CWE-120 \
    --max-samples 100 \
    --out datasets/juliet_cwe120.json
```

Create a group-safe split:

```bash
python scripts/split_juliet_manifest.py \
    datasets/juliet_cwe120.json \
    --train-out datasets/juliet_train.json \
    --test-out datasets/juliet_test.json \
    --test-ratio 0.2 \
    --seed 42
```

Run the benchmark:

```bash
python scripts/run_juliet_benchmark.py \
    datasets/juliet_test.json \
    --out results/juliet_phase1.json
```

Start with a small subset and verify the toolchain before scaling to the full benchmark.

---

# Research Reproducibility

Every experiment should record:

- dataset and version;
- dataset split seed;
- CWE subset;
- analyzer versions;
- LLM provider/model;
- model temperature/configuration where applicable;
- system configuration;
- number of analyzed files;
- evaluation output;
- matching strategy;
- timestamp.

The repository should keep raw findings and final evaluation results separate.

A recommended experiment directory is:

```text
results/
└── experiment_001/
    ├── config.json
    ├── raw_findings.jsonl
    ├── phase1_results.json
    ├── phase2_results.json
    ├── metrics.json
    └── comparison.csv
```

This makes experiments auditable and repeatable.

---

# Current Status

## Implemented / research core

- [x] Tree-sitter structural-analysis layer
- [x] Python/C/C++ language support in the structural layer
- [x] Static-analysis adapters
- [x] Normalized finding schema
- [x] Finding correlation/deduplication
- [x] Multi-agent verification architecture
- [x] Structured evidence and adjudication states
- [x] Precision / Recall / F1 evaluation
- [x] False Positive Rate and related metrics
- [x] Per-CWE evaluation
- [x] Juliet manifest generation
- [x] Juliet group-safe splitting
- [x] Benchmark execution framework
- [x] Automated unit tests for the research components

## In progress

- [ ] Full integration with the existing application/AutoGen UI
- [ ] Full Juliet C/C++ 1.3 benchmark run
- [ ] Baseline result collection
- [ ] LLM-model comparison
- [ ] Ablation experiments
- [ ] Real-world CVE case-study evaluation
- [ ] Final result visualization

## Not the primary research target

The following are intentionally secondary until the research evaluation is stable:

- automatic vulnerability repair;
- enterprise deployment;
- broad multi-language expansion beyond the initial target languages;
- production-scale distributed execution;
- advanced UI features.

---

# Limitations

The system has several important limitations that should be acknowledged in the final research report.

1. **Static-analysis coverage is tool-dependent.** Different analyzers detect different vulnerability classes and use different matching/reporting models.
2. **LLM judgments are probabilistic.** The system therefore records an `UNCERTAIN` state instead of forcing a binary decision when evidence is insufficient.
3. **Finding matching is itself an experimental choice.** Line/CWE/function-based matching can produce different outcomes from semantic or patch-level matching.
4. **Juliet contains synthetic and benchmark-oriented code.** It is valuable for controlled evaluation but should be complemented by real-world case studies.
5. **Interprocedural analysis remains more difficult than local structural analysis.** The first implementation emphasizes evidence extraction and controlled verification before adding deeper whole-program analysis.

---

# Roadmap

```text
Phase 1  ─ Deterministic structural/static analysis       ✅
Phase 2  ─ Multi-agent verification                      ✅
Phase 3  ─ Benchmark + metrics                           ✅

Next     ─ Full Juliet baseline experiments              🚧
Next     ─ Ablation studies                              🚧
Next     ─ Real-world CVE case studies                   🚧
Next     ─ Statistical analysis of results               🚧
Next     ─ Final AutoGen/UI integration                  🚧
Next     ─ Research report / thesis evaluation           🚧
```

---

# Research Contribution

The intended contribution is not simply another LLM-based vulnerability scanner.

The project investigates a specific hypothesis:

```text
Traditional Static Analysis
            +
Structural Program Evidence
            +
Specialized LLM Reasoning
            +
Adversarial Verification
            ↓
Better Vulnerability Triage
            ↓
Fewer False Positives
            while preserving Recall
```

The contribution should ultimately be supported by experimental evidence, not only by the architecture.

A successful evaluation should demonstrate, for the selected benchmark and matching methodology, whether the proposed system:

1. reduces false positives relative to static-analysis baselines;
2. preserves or improves recall;
3. performs consistently across multiple CWE categories;
4. benefits specifically from structural information and multi-agent verification.

---

# References

1. Johnson, B., Song, Y., Murphy-Hill, E., and Bowdidge, R. *Why Don't Software Developers Use Static Analysis Tools to Find Bugs?* ICSE, 2013.
2. Evans, D. and Larochelle, D. *Improving Security Using Extensible Lightweight Static Analysis.* IEEE Software, 2002.
3. Zhou, Y., Liu, S., Siow, J., Du, X., and Liu, Y. *Devign: Effective Vulnerability Identification by Learning Comprehensive Program Semantics via Graph Neural Networks.* NeurIPS, 2019.
4. Tree-sitter documentation: https://tree-sitter.github.io/tree-sitter/
5. Bandit: https://github.com/PyCQA/bandit
6. Cppcheck: https://github.com/danmar/cppcheck
7. Flawfinder: https://github.com/david-a-wheeler/flawfinder
8. Clang Static Analyzer: https://clang.llvm.org/docs/ClangStaticAnalyzer.html
9. Juliet Test Suite / NIST SARD: https://samate.nist.gov/

---

## License

Add the project's chosen license here. If this repository is intended for academic/public release, a standard open-source license should be selected before publication.
