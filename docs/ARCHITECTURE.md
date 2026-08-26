# Architecture

## Design goals

1. Deterministic analyzers produce evidence before an LLM is invoked.
2. Findings from multiple tools share one schema.
3. LLM agents have narrow responsibilities.
4. The critic explicitly searches for false-positive explanations.
5. Evaluation is independent of the decision-making code.

## Core interfaces

### Phase 1

`Phase1Pipeline.analyze_file(path)` returns a JSON-compatible report containing:

- source and language
- structural Tree-sitter representation
- normalized findings
- correlated finding groups
- tool availability/errors

### Phase 2

`Phase2Pipeline.analyze_report(report)` consumes the Phase 1 JSON-compatible report and returns:

- agent assessments
- final adjudication
- evidence
- confidence
- tool support
- decision counts

### Phase 3

`phase3.evaluate(experiment, predictions, ground_truth)` is independent from the scanner and LLM layers. This makes it possible to compare different prediction sources with exactly the same evaluation policy.

## Data flow

```text
Raw source
  -> parser/indexer
  -> static tools
  -> Finding objects
  -> correlation groups
  -> evidence packet
  -> specialized agents
  -> adversarial critic
  -> adjudication
  -> Prediction objects
  -> GroundTruth matcher
  -> metrics
```

## Why the layers are separated

If the same code both detects a vulnerability and decides whether the detection is correct, an experiment cannot cleanly determine what caused a performance improvement. The separation here makes it possible to say, for example:

- static analyzer generated a candidate;
- structure provided context;
- critic rejected the candidate because the length constraint was proven;
- benchmark classified the decision against ground truth.
