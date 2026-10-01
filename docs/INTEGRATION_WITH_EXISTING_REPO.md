# Integration with the existing GitHub repository

This bundle contains the consolidated research core from Phases 1–3. Your existing application has additional AutoGen/API/UI files that should remain in the main checkout.

## Merge procedure

1. Copy `analyzers/` into the repository.
2. Copy `phase2/` and `phase3/` into the repository.
3. Keep your existing `agents/`, `config/`, API, UI, and deployment files. The
   Scanner and Verifier agents in `agents/scanner_agent.py` and
   `agents/verifier_agent.py` subclass `agents/security_agent.py`, so if you
   rename that module, update the two imports in them.
4. Merge the new requirements into your existing requirements file instead of replacing it wholesale.
5. Add the `scripts/` directory (`run_phase2.py`, `run_benchmarks.py`,
   `run_llm_only_benchmark.py`, `eval_taint_evidence.py`,
   `aggregate_phase3.py`, `doctor.py`) and copy `data/cve_catalog.json`. The
   catalogue is loaded by absolute path from `analyzers/catalog.py`, so it has
   to sit next to the `analyzers` package.
6. Run `pytest -q` and then `python scripts/doctor.py`.

## Entry points

| Stage | Command |
| --- | --- |
| Phase 1, one file or directory | `python -m analyzers.phase1_pipeline <path> --out results/phase1_report.json` |
| Phase 2, Scanner → Verifier | `python scripts/run_phase2.py results/phase1_report.json --out results/phase2_report.json` |
| Phase 2, single-agent baseline | the same command with `--architecture single_agent` |
| Phase 3 | `python -m codey_security phase3`, or the scripts under `scripts/` |
| Full benchmark ladder | `python scripts/run_benchmarks.py --list` (then `--dry-run`, then run) |
| Everything | `python -m codey_security full` |

`make help` lists the same targets as short aliases.

`python -m codey_security` reads `PHASE2_ARCHITECTURE` and builds the
multi-agent pipeline by default; setting it to `single_agent` routes the same
Phase 1 reports through the merged-role baseline instead.

## Phase 2 dependency contract

`phase2/llm.py` and `phase2/client.py` import the `agents` package at runtime.
This is intentional: Phase 2 should use the same provider and configuration
stack as the rest of the application instead of introducing a second LLM
implementation. `phase2/multiagent.py` has no LLM dependency at all — it is
written against an `ask_json` callable, which is what lets the orchestration be
tested without a model.
