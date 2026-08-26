# Integration with the existing GitHub repository

This bundle contains the consolidated research core from Phases 1–3. Your existing application has additional AutoGen/API/UI files that should remain in the main checkout.

## Merge procedure

1. Copy `analyzers/` into the repository.
2. Copy `phase2/` and `phase3/` into the repository.
3. Keep your existing `agents/`, `config/`, API, UI, and deployment files.
4. Merge the new requirements into your existing requirements file instead of replacing it wholesale.
5. Add the top-level scripts (`run_pipeline.py`, `run_phase2.py`, `run_phase3.py`, `aggregate_phase3.py`).
6. Run `pytest -q` and then `python scripts/doctor.py`.

## Phase 2 dependency contract

`phase2/llm.py` imports the existing `agents.enhanced_multi_agent_system` abstraction at runtime. This is intentional: Phase 2 should use the same provider/configuration stack as the rest of your application instead of introducing a second LLM implementation.
