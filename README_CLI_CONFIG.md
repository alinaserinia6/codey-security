# Unified CLI and Configuration

The three previous entry points are consolidated into `codey_security.py`.

## Commands

```bash
python codey_security.py phase1 examples/cpp/vulnerable.cpp
python codey_security.py phase2 examples/cpp/vulnerable.cpp --provider ollama
python codey_security.py phase3 datasets/juliet_test.json --mode phase1
python codey_security.py phase3 datasets/juliet_test.json --mode phase2 --provider ollama
```

Run Phase 1 + Phase 2 together:

```bash
python codey_security.py full examples/cpp/vulnerable.cpp
```

Run all three stages, including benchmark evaluation:

```bash
python codey_security.py full examples/cpp/vulnerable.cpp \
  --dataset datasets/juliet_test.json \
  --provider ollama
```

## Configuration

All environment configuration is centralized in `env_config.py`. Copy `.env.example` to `.env` and change the values you need.

The module reads environment variables without overriding variables already exported by the shell. Real API keys should never be committed.

The old `run_pipeline.py`, `run_phase2.py`, and `run_phase3.py` remain as compatibility wrappers; new documentation and scripts should use `codey_security.py`.
