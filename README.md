# Codey-Security

## Combining Code Structural Analysis with Large Language Model Reasoning and Multi-Agent Architecture to Reduce False Positives in Code Vulnerability Assessment

Codey-Security is a research project focused on improving **Static Application Security Testing (SAST)** by combining traditional code structural analysis, Large Language Models (LLMs), and a multi-agent architecture.

The main goal is to reduce **false positives** in source-code vulnerability assessment while maintaining effective vulnerability detection.

---

## 🎯 Project Goal

Static Application Security Testing tools are widely used to identify security vulnerabilities in source code. However, traditional static-analysis approaches can generate a large number of false positives.

Codey-Security aims to address this problem by combining:

- Source-code structural analysis
- Abstract Syntax Tree (AST) analysis
- Intra-procedural data-flow analysis
- Source-to-sink analysis
- Large Language Model reasoning
- Multi-agent architecture
- Vulnerability verification

The system focuses on analyzing source code and providing more reliable vulnerability assessments.

---

## 🔍 Supported Vulnerability Categories

The project focuses on several important vulnerability categories, including:

- Injection
- Command Injection
- Template Injection
- Code Injection
- Buffer Overflow
- Integer Overflow
- Unsafe Deserialization
- Server-Side Template Injection (SSTI)

The system is designed to analyze relationships between sources, sinks, sanitization mechanisms, and vulnerable operations.

---

## 🏗️ System Architecture

### Main Components

```text
                     Source Code
                          │
                          ▼
                  Code Structural
                     Analysis
                          │
                          ▼
                     AST Analysis
                          │
                          ▼
                  Scanner Agent
                          │
                          ▼
                Vulnerability Candidates
                          │
                          ▼
                  Verifier Agent
                          │
                          ▼
                  LLM Reasoning
                          │
                          ▼
                  Final Assessment
                          │
                          ▼
                   JSON / Report
```

### Scanner Agent

The **Scanner Agent** is responsible for identifying potential vulnerabilities from the source code.

It uses structural information extracted from the program to identify suspicious code patterns and potential source-to-sink flows.

### Verifier Agent

The **Verifier Agent** examines the vulnerabilities reported by the scanner.

Its purpose is to determine whether a reported vulnerability is actually exploitable or whether the finding is likely to be a false positive.

The verifier can use:

- AST information
- Data-flow information
- Source-to-sink relationships
- Code context
- LLM reasoning

The final objective is to improve the reliability of vulnerability reports.

---

## 🔄 Analysis Workflow

```text
Source Code
    │
    ▼
Parse Source Code
    │
    ▼
Build AST
    │
    ▼
Extract Structural Information
    │
    ▼
Identify Potential Vulnerabilities
    │
    ▼
Scanner Agent
    │
    ▼
Verifier Agent
    │
    ▼
LLM-Based Reasoning
    │
    ▼
Validate Vulnerability
    │
    ▼
Generate Final Report
```

The system combines deterministic structural analysis with LLM-based reasoning rather than relying exclusively on an LLM.

---

## 🧠 Structural Code Analysis

The system uses structural analysis to provide the LLM with relevant information about the program.

- AST parsing with Tree-sitter
- Source-code structure extraction
- Intra-procedural analysis
- Source-to-sink analysis
- Vulnerability candidate identification
- Code-context extraction

---

## 🤖 Multi-Agent Architecture

The project uses a multi-agent architecture in which different agents have specialized responsibilities.

### Scanner Agent

Responsible for:

- Initial vulnerability detection
- Identifying suspicious code
- Locating potential vulnerability sources and sinks
- Producing vulnerability candidates

### Verifier Agent

Responsible for:

- Reviewing scanner findings
- Analyzing the surrounding code context
- Checking source-to-sink relationships
- Determining whether a finding is likely valid
- Reducing false positives

---

## 🧩 Technologies

| Technology             | Purpose                                       |
| ---------------------- | --------------------------------------------- |
| **Tree-sitter**        | Source-code parsing and AST generation        |
| **AutoGen**            | Multi-agent architecture                      |
| **LangChain**          | LLM integration and orchestration             |
| **LLM APIs**           | Code reasoning and vulnerability verification |
| **Visual Studio Code** | Development environment                       |
| **Linux**              | Primary execution environment                 |

---

## 🐍 Python and C Support

The project targets two programming languages:

- **Python**
- **C**

Different vulnerabilities and analysis tools are used for the two languages.

### Python

The project uses **Bandit** as the baseline static-analysis tool for Python.

### C

The project uses **Flawfinder** as the baseline static-analysis tool for C.

---

## 🐛 Target CVEs

The project includes four specific CVEs as real-world vulnerability cases.

### C

#### CVE-2021-3156

A vulnerability in **Sudo**.

```text
Language: C
Project: Sudo
CVE: CVE-2021-3156
```

#### CVE-2017-7529

A vulnerability in **Nginx**.

```text
Language: C
Project: Nginx
CVE: CVE-2017-7529
```

### Python

#### CVE-2021-25239

A vulnerability associated with **Jinja/Flask**.

```text
Language: Python
Project: Jinja/Flask
CVE: CVE-2021-25239
```

#### CVE-2022-22817

A vulnerability associated with **PyYAML**.

```text
Language: Python
Project: PyYAML
CVE: CVE-2022-22817
```

---

## 📊 Evaluation Methodology

The evaluation is designed to compare the codey-security against existing static-analysis tools.

The main baseline tools are:

```text
Python → Bandit
C      → Flawfinder
```

Codey-security is then evaluated against these baselines.

---

### 📚 Evaluation Datasets

#### NIST SARD

The **Software Assurance Reference Dataset (SARD)** contains a large collection of programs with known vulnerabilities and is intended for evaluating software-security tools.

#### Juliet Test Suite

The **Juliet Test Suite** provides test cases covering many CWE categories and is particularly useful for evaluating vulnerability-detection tools.

The project can use Juliet to evaluate vulnerability detection using known vulnerable and safe examples. 

#### Devign

**Devign** is a vulnerability-detection dataset containing vulnerable code from real-world projects.

#### Vul-Big

**Vul-Big** contains vulnerable code associated with CVEs and commits and can be used for evaluating vulnerability detection on real-world vulnerabilities. 

---

## 📈 Evaluation Metrics

The primary evaluation metrics are:

- Precision
- Recall

The evaluation compares the vulnerability findings generated by the baseline tools and the codey-security against the known ground truth.

### Precision

Precision measures how many reported vulnerabilities are actually vulnerabilities.

```text
Precision = TP / (TP + FP)
```

Where:

- `TP` = True Positives
- `FP` = False Positives

A higher precision indicates fewer false-positive reports.

### Recall

Recall measures how many of the actual vulnerabilities are successfully detected.

```text
Recall = TP / (TP + FN)
```

Where:

- `TP` = True Positives
- `FN` = False Negatives

A higher recall indicates that fewer vulnerabilities are missed.

---

## 🎯 Main Research Objective

The central objective of Codey-Security is to improve vulnerability-assessment reliability by reducing false positives.

The codey-security combines:

```text
Traditional Static Analysis
          +
Code Structural Analysis
          +
AST Analysis
          +
Source-to-Sink Analysis
          +
LLM Reasoning
          +
Multi-Agent Verification
          ↓
More Reliable Vulnerability Assessment
```

The key research question is whether combining structural code information with LLM reasoning and multi-agent verification can reduce false-positive vulnerability reports while maintaining effective detection.

---

## 🧪 Evaluation Process

The evaluation process consists of the following stages:

### Step 1 — Prepare the Dataset

Collect vulnerable and safe source-code samples from:

- NIST SARD
- Juliet Test Suite
- Devign
- Vul-Big
- The four target CVEs

### Step 2 — Run Baseline Tools

Run:

```text
Bandit   → Python
Flawfinder → C
```

and record their findings.

### Step 3 — Run Codey-Security

Run the codey-security on the same evaluation samples.

### Step 4 — Compare Results

Compare the predicted vulnerabilities with the ground-truth labels.

### Step 5 — Calculate Metrics

Calculate:

```text
True Positives
False Positives
True Negatives
False Negatives
Precision
Recall
```

### Step 6 — Analyze False Positives

Investigate cases where the baseline tools report vulnerabilities that are not actually exploitable.

The purpose of the verifier and LLM reasoning components is to determine whether these findings can be rejected based on structural and contextual evidence.

---

## 🗂️ Expected Output

The system should produce structured vulnerability reports containing information such as:

```json
{
  "vulnerability": true,
  "cwe": "CWE-XXX",
  "cve": "CVE-XXXX-XXXXX",
  "file": "example.c",
  "line": 42,
  "source": "...",
  "sink": "...",
  "reason": "...",
  "confidence": 0.0
}
```

The exact output format can be adapted during implementation.

---

## 🔬 Research Workflow

The overall research workflow is:

```text
                Dataset
                   │
                   ▼
          Baseline Evaluation
                   │
          ┌────────┴────────┐
          ▼                 ▼
       Bandit           Flawfinder
          │                 │
          └────────┬────────┘
                   ▼
             Codey-Security
                   │
          ┌────────┴────────┐
          ▼                 ▼
     Scanner Agent     Verifier Agent
          │                 │
          └────────┬────────┘
                   ▼
              LLM Reasoning
                   │
                   ▼
             Final Findings
                   │
                   ▼
          Precision / Recall
                   │
                   ▼
        False-Positive Analysis
```

---

## 🛠️ Development Environment

- Linux
- Visual Studio Code
- Python
- C
- LLM APIs

Visual Studio Code is used as the development environment, while Linux is identified as the target execution environment. 

---

## 📁 Project Structure

```text
Codey-Security/
│
├── agents/
│   ├── scanner_agent/
│   └── verifier_agent/
│
├── analysis/
│   ├── ast/
│   ├── dataflow/
│   └── source_sink/
│
├── parsers/
│   └── tree_sitter/
│
├── evaluation/
│   ├── datasets/
│   ├── bandit/
│   ├── flawfinder/
│   └── metrics/
│
├── reports/
│
├── tests/
│
└── README.md
```

---

## 📌 Key Research Components

The project combines the following concepts:

- Static Application Security Testing (SAST)
- Source-code analysis
- Abstract Syntax Trees (ASTs)
- Intra-procedural analysis
- Source-to-sink analysis
- Vulnerability detection
- Large Language Models
- Intelligent agents
- Multi-agent architecture
- Vulnerability verification
- False-positive reduction

---

## 📚 References

1. B. Johnson, Y. Song, E. Murphy-Hill, and R. Bowdidge, *Why Don’t Software Developers Use Static Analysis Tools to Find Bugs?*, Proceedings of the 35th International Conference on Software Engineering (ICSE), 2013.

2. N. Ayewah and W. Pugh, *The Google FindBugs Fixit*, Proceedings of the 19th International Symposium on Software Testing and Analysis (ISSTA), 2010.

3. Z. Chen, S. Fan, Y. Zhao, and X. Liu, *Large Language Models for Code Analysis: A Survey*, arXiv preprint, 2023.

4. S. Zhang, H. Chen, and Y. Zhou, *On the Reliability of Large Language Models for Software Vulnerability Detection*, arXiv preprint, 2023.

5. Y. Zhou, S. Liu, J. Siow, X. Du, and Y. Liu, *Devign: Effective Vulnerability Identification by Learning Comprehensive Program Semantics via Graph Neural Networks*, NeurIPS, 2019.

6. D. Evans and D. Larochelle, *Improving Security Using Extensible Lightweight Static Analysis*, IEEE Software, vol. 19, no. 1, pp. 42–51, 2002.

7. F. Wu, X. Wang, Y. Liu, and Z. Zhang, *AutoAudit: Automated Code Auditing with Multi-Agent Systems*, arXiv preprint, 2024.

8. MITRE, *Common Weakness Enumeration (CWE)*.

---

## 🔗 Useful Resources

- [Tree-sitter](https://tree-sitter.github.io/tree-sitter/)
- [Microsoft AutoGen](https://microsoft.github.io/autogen/)
- [LangChain](https://www.langchain.com/docs/)
- [OpenAI Platform](https://platform.openai.com/docs/)
- [Devign](https://github.com/fuxudong/Devign)
- [NIST SARD](https://samate.nist.gov/SARD/)
- [CWE](https://cwe.mitre.org/)
- [CVE](https://cve.mitre.org/)

---

## 📄 Project Status

Codey-Security is a research project focused on evaluating whether a combination of structural code analysis, LLM reasoning, and multi-agent verification can reduce false positives in source-code vulnerability assessment.

The evaluation will use established vulnerability datasets, baseline static-analysis tools, and real-world CVE cases to measure the effectiveness of the codey-security.
