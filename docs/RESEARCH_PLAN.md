# Research plan

## Hypothesis

Combining source-code structure and static-analysis evidence with independent multi-agent verification reduces false positives while preserving vulnerability recall.

## Baselines

1. Static tools only
2. LLM-only source review
3. Static findings + one LLM reviewer
4. Static findings + structural context + multi-agent verification

## Ablations

Remove one component at a time:

- no AST/context
- no critic
- no independent security agent
- no static tools
- no correlation/deduplication

## Controls

- same dataset
- same benchmark split
- same vulnerability classes
- same matching policy
- fixed temperature during evaluation
- recorded model/provider versions
- repeated runs when model nondeterminism matters

## Main claim to test

The useful result is not simply that a multi-agent system finds vulnerabilities. The key test is whether its **false-positive rate decreases without an unacceptable loss in recall** relative to the baselines.
