# CLI and scenario configuration

Codey-Security has one entry point and a deliberately minimal command line.
The command only selects the scenario. All paths, model settings, evaluation
options and input references are configured in `env_config.py` or `.env`.

## Commands

```bash
python codey_security.py phase1
python codey_security.py phase2
python codey_security.py phase3
python codey_security.py full
```

There are intentionally no `--provider`, `--out`, `--dataset`, `--mode`, or
other runtime options.

Phase 2 always uses the single DeepSeek Security Agent over the LLM
API. The model is selected with `LLM_MODEL`.

## Scenario references

The default references are defined in `_make_scenarios()` inside
`env_config.py` and can be overridden through `.env`:

```dotenv
SCENARIO_PHASE1_SOURCE=examples/cpp/vulnerable.cpp
SCENARIO_PHASE2_SOURCE=examples/cpp/vulnerable.cpp
SCENARIO_PHASE3_DATASET=datasets/juliet_test.json
SCENARIO_PHASE3_MODE=phase1
SCENARIO_FULL_SOURCE=examples/cpp/vulnerable.cpp
SCENARIO_FULL_DATASET=datasets/juliet_test.json
SCENARIO_FULL_MODE=phase2
```

A user only runs `phase1`, `phase2`, `phase3`, or `full`; the configuration
determines exactly what each scenario means.

## Configuration precedence

1. Variables exported in the shell.
2. Values in `.env` that are not already exported.
3. Defaults defined in `env_config.py`.

Copy the template first:

```bash
cp .env.example .env
```

Never commit `.env` or API keys.

## Recommended repository policy

Keep `env_config.py` as the single source of truth for typed configuration and
scenario definitions. Keep `.env` for machine-specific overrides such as API
keys, model names, dataset locations and experiment paths.
