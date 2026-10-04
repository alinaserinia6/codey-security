#!/usr/bin/env python3
"""One-shot benchmark runner: choose exactly what you want, run it, paste back.

Everything is selected on the command line -- which suites, which legs, which
datasets, which manifest the LLM subset is cut from, the model and the tag --
so the same script covers a 2-minute smoke run and the full evaluation.

Legs
    A  static tools only (Bandit / Flawfinder / cppcheck), no LLM
    B  LLM only: one full source file, no static evidence
    C  static findings + LLM, no structural evidence (ablation)
    D  static findings + structural evidence + LLM (proposed system)
    E  deterministic source-to-sink evidence vs the language's baseline tool

Suites group the legs: ``static`` = A, ``llm`` = B/C/D (plus A on the same
subset so every row is comparable), ``taint`` = E.  ``--legs`` filters inside
a suite, e.g. ``--suite llm --legs C,D``.

E picks the baseline tool from the dataset's language (C -> Flawfinder,
Python -> Bandit); a mixed-language manifest is split per language first, so
both populations get the tool that applies to them.

Usage (run from the repo root)::

    python scripts/run_benchmarks.py --list
    python scripts/run_benchmarks.py --dry-run --suite all
    python scripts/run_benchmarks.py --suite static,taint          # no API key
    python scripts/run_benchmarks.py --suite llm --llm-limit 30 --tag smoke30
    python scripts/run_benchmarks.py --suite llm \\
        --llm-source vulnllm_r_python --llm-limit 30 --tag py30

At the end the script prints a RESULT block. Copy-paste that whole block back
and the analysis can continue without re-running anything.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from env_config import get_config  # noqa: E402 -- importing loads .env into
# os.environ (no override of already-exported vars) so every child benchmark
# process inherits the same configuration as `python codey_security.py`.

from agents.openai_compat import resolve_transport  # noqa: E402

# Short name -> manifest path, in report order.
MANIFESTS: Dict[str, str] = {
    "vulnllm_r_c": "datasets/vulnllm_r_c.json",
    "vulnllm_r_c_dataflow": "datasets/vulnllm_r_c_dataflow.json",
    "vulnllm_r_python": "datasets/vulnllm_r_python.json",
    "vulnllm_r_repo_c": "datasets/vulnllm_r_repo_c.json",
    "python_bench": "datasets/python_bench/python_bench.json",
    "proposal_min10": "datasets/proposal_min10.json",
    "primevul": "datasets/primevul_test_paired.json",
    "bigvul": "datasets/bigvul_test.json",
}

# The manifest the LLM legs cut their subset from. Anything in MANIFESTS can
# be named with --llm-source, which is how the Python population gets judged
# by the model instead of only by the deterministic tools.
DEFAULT_LLM_SOURCE = "vulnllm_r_c_dataflow"

# Which baseline tool scores a language in leg E.
TAINT_BASELINE = {"c": "flawfinder", "python": "bandit"}

LEGS = ("A", "B", "C", "D", "E")
SUITES = ("static", "taint", "llm")


def log(message: str) -> None:
    print(f"[bench] {message}", flush=True)


def manifest_info(path: str) -> Tuple[int, int, List[str]]:
    """(samples, vulnerable, languages) for a manifest, without failing a run
    on a manifest that cannot be read -- the count is diagnostic only."""
    try:
        payload = json.loads((REPO_ROOT / path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return 0, 0, []
    samples = payload.get("samples") if isinstance(payload, dict) else payload
    if not isinstance(samples, list):
        return 0, 0, []
    languages = sorted({str(s.get("language") or "unknown") for s in samples})
    vulnerable = sum(1 for s in samples if s.get("vulnerable"))
    return len(samples), vulnerable, languages


def run_step(name: str, argv: List[str], env: Optional[dict] = None,
             timeout: Optional[int] = None) -> tuple:
    """Run one step, streaming the child's output live, never raising.

    Long LLM steps print progress for minutes without finishing, so every
    child line is echoed immediately as ``[step] line``; the last lines are
    also kept for the failure tail. Returns (ok, elapsed_seconds, tail).
    """
    import collections
    import threading

    started = time.perf_counter()
    merged = dict(os.environ)
    if env:
        merged.update(env)
    print(f"[bench] start {name}: {' '.join(argv)}", flush=True)
    tail: collections.deque = collections.deque(maxlen=20)
    try:
        proc = subprocess.Popen(
            argv, cwd=str(REPO_ROOT), env=merged,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )

        def pump() -> None:
            assert proc.stdout is not None
            for line in proc.stdout:
                line = line.rstrip()
                if line:
                    print(f"[{name}] {line}", flush=True)
                    tail.append(line)

        reader = threading.Thread(target=pump, daemon=True)
        reader.start()
        try:
            ret = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            return False, time.perf_counter() - started, ["TIMEOUT"]
        reader.join(timeout=10)
        ok = ret == 0
        lines = list(tail)[-4:]
        if not ok:
            lines = [f"exit={ret}"] + lines
        return ok, time.perf_counter() - started, lines
    except Exception as exc:  # noqa: BLE001 - one step must not kill the run
        return False, time.perf_counter() - started, [f"{type(exc).__name__}: {exc}"]


def llm_reachable(timeout: int = 8) -> tuple:
    """Probe the endpoint the run will actually call.

    An OpenCode server exposes ``/provider``; an OpenAI-compatible provider
    (Apmix, OpenRouter, ...) exposes ``/models`` and needs the API key. Probing
    the wrong one reports "unreachable" and silently skips every LLM leg.
    """
    cfg = get_config()
    base = cfg.llm_base_url
    transport = resolve_transport(base)
    try:
        if transport == "openai":
            request = urllib.request.Request(base.rstrip("/") + "/models")
            key = os.environ.get("LLM_API_KEY") or os.environ.get("OPENAI_API_KEY")
            if key:
                request.add_header("Authorization", f"Bearer {key}")
            with urllib.request.urlopen(request, timeout=timeout) as resp:
                body = resp.read().decode("utf-8", "replace")
            model = cfg.llm_model_id
            listed = False
            try:
                ids = {
                    str(item.get("id", ""))
                    for item in json.loads(body).get("data", [])
                }
                listed = model in ids
            except (ValueError, AttributeError, TypeError):
                pass
            note = f"model={model} {'listed' if listed else 'NOT LISTED'}"
            return True, f"{base} answered HTTP 200 (openai, {note})"
        with urllib.request.urlopen(base + "/provider", timeout=timeout) as resp:
            return True, f"{base} answered HTTP {resp.status} (opencode)"
    except Exception as exc:  # noqa: BLE001 - probe must not raise
        return False, f"{base} unreachable ({transport}): {type(exc).__name__}: {exc}"


def read_metrics(path: Path) -> Optional[dict]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    metrics = payload.get("metrics", {})
    if "confusion" in metrics:  # Phase 3 report shape
        out = dict(metrics["confusion"])
        for key in ("precision", "recall", "f1", "false_positive_rate",
                    "accuracy", "specificity"):
            out[key] = metrics.get(key)
        return out
    if "any_source_to_sink_path" in metrics:  # taint evidence shape
        return metrics.get("source_to_sink_path_without_mitigation")
    return None


def fmt_row(metrics: Optional[dict]) -> str:
    if not metrics:
        return "FAILED"
    def number(key: str) -> str:
        value = metrics.get(key)
        return f"{value:.4f}" if isinstance(value, float) else str(value)
    conf = " ".join(f"{k}={metrics.get(k)}" for k in ("tp", "fp", "fn", "tn"))
    return f"{conf} P={number('precision')} R={number('recall')} F1={number('f1')}"


def build_static_steps(names: List[str], results: Path) -> List[dict]:
    steps = []
    for name in names:
        out = results / f"exp_{name}_static.json"
        steps.append({
            "name": f"A/{name}",
            "leg": "A",
            "argv": [sys.executable, "codey_security.py", "phase3"],
            "env": {"SCENARIO_PHASE3_MODE": "phase1",
                    "SCENARIO_PHASE3_DATASET": MANIFESTS[name],
                    "SCENARIO_PHASE3_OUTPUT": str(out)},
            "timeout": 3600,
            "row": f"A static {name}",
            "out": out,
        })
    return steps


def build_taint_steps(names: List[str], results: Path) -> List[dict]:
    """Leg E per dataset, split by language when a manifest mixes them.

    The baseline tool has to be the one a developer would actually run for
    that language, so a C manifest is scored with Flawfinder and a Python one
    with Bandit; a mixed manifest is filtered into per-language manifests
    first (filter_manifest keeps paths relative to datasets/, which is where
    the sources live).
    """
    steps = []
    for name in names:
        manifest = MANIFESTS[name]
        _, _, languages = manifest_info(manifest)
        applicable = [lang for lang in languages if lang in TAINT_BASELINE]
        if not applicable:
            steps.append({
                "name": f"E/{name}",
                "leg": "E",
                "skip": f"no taint table for {','.join(languages) or 'unknown'}",
                "row": f"E taint {name}",
            })
            continue
        plans: List[Tuple[str, str]] = []
        if len(languages) == 1:
            plans.append((manifest, applicable[0]))
        else:
            # Split first, then score each side with its own tool. The filter
            # steps are appended before the eval steps below so a run never
            # evaluates a manifest that has not been written yet.
            for lang in applicable:
                filtered = f"datasets/_taint_{name}_{lang}.json"
                steps.append({
                    "name": f"E/{name}/{lang}-filter",
                    "leg": "E",
                    "argv": [sys.executable, "scripts/filter_manifest.py",
                             "--in", manifest, "--out", filtered,
                             "--language", lang],
                    "timeout": 600,
                    "filter_out": filtered,
                })
                plans.append((filtered, lang))
        for manifest_path, lang in plans:
            out = (results / f"exp_{name}_taint.json" if len(languages) == 1
                   else results / f"exp_{name}_taint_{lang}.json")
            steps.append({
                "name": f"E/{name}" + ("" if len(languages) == 1 else f"/{lang}"),
                "leg": "E",
                "argv": [sys.executable, "scripts/eval_taint_evidence.py",
                         "--dataset", manifest_path,
                         "--baseline", TAINT_BASELINE[lang],
                         "--out", str(out)],
                "timeout": 3600,
                "row": f"E taint {name}" + ("" if len(languages) == 1 else f" [{lang}]"),
                "out": out,
            })
    return steps


def build_llm_steps(args, names: List[str], results: Path,
                    budget: str) -> Tuple[List[dict], str, List[str]]:
    """Steps for A-subset/B/C/D plus the subset manifest they share."""
    source = args.llm_source
    if source not in MANIFESTS:
        raise SystemExit(
            f"error: unknown --llm-source {source!r}; choose from {sorted(MANIFESTS)}"
        )
    subset = REPO_ROOT / "datasets" / f"llm_subset_{source}_{args.llm_limit}.json"
    tag = args.tag or f"{source}_{args.llm_limit}"
    summary: List[str] = [budget]
    steps: List[dict] = [{
        "name": "subset",
        "leg": "B/C/D",
        "argv": [sys.executable, "scripts/filter_manifest.py",
                 "--in", MANIFESTS[source], "--out", str(subset),
                 "--limit", str(args.llm_limit)],
        "timeout": 600,
        "summary": f"subset {source}: {args.llm_limit} samples -> {subset.name}",
    }]

    # A on the same subset, so every row is comparable.
    if args.legs & {"A"}:
        out_a = results / f"exp_{tag}_A_static.json"
        steps.append({
            "name": "A-sub", "leg": "A",
            "argv": [sys.executable, "codey_security.py", "phase3"],
            "env": {"SCENARIO_PHASE3_MODE": "phase1",
                    "SCENARIO_PHASE3_DATASET": str(subset),
                    "SCENARIO_PHASE3_OUTPUT": str(out_a)},
            "timeout": 3600, "row": f"A static {tag}", "out": out_a,
        })

    if args.legs & {"B"}:
        pred = results / f"exp_{tag}_B_llm_only.jsonl"
        b_args = [sys.executable, "scripts/run_llm_only_benchmark.py",
                  "--dataset", str(subset), "--out", str(pred),
                  "--concurrency", str(args.concurrency),
                  "--timeout", str(args.llm_timeout), "--resume"]
        if args.model:
            b_args += ["--model", args.model]
        steps.append({
            "name": "B", "leg": "B", "argv": b_args,
            "env": {"LLM_THINKING_OUT":
                    str(results / f"exp_{tag}_B_llm_only.thinking.json")},
            "timeout": 10800,
            # The row lives on B-eval (metrics only exist after it runs), so
            # without this the prediction step's minutes would be reported as
            # the eval step's seconds: B looked like "ok (0s)".
            "part_of": "B",
        })
        be_args = [sys.executable, "scripts/evaluate_llm_only.py",
                   "--dataset", str(subset), "--predictions", str(pred),
                   "--out", str(results / f"exp_{tag}_B_llm_only.json")]
        if args.model:
            be_args += ["--model", args.model]
        steps.append({
            "name": "B-eval", "leg": "B", "argv": be_args, "timeout": 600,
            "row": f"B llm-only {tag}",
            "out": results / f"exp_{tag}_B_llm_only.json",
            "part_of": "B",
        })

    if args.legs & {"C"}:
        out_c = results / f"exp_{tag}_C_static_llm.json"
        steps.append({
            "name": "C", "leg": "C",
            "argv": [sys.executable, "codey_security.py", "phase3"],
            "env": {"PHASE2_INCLUDE_STRUCTURAL": "false",
                    # The multi-agent legs size their worker pool from
                    # PHASE2_CONCURRENCY; B honours --concurrency, and without
                    # this C and D silently ran at 4.
                    "PHASE2_CONCURRENCY": str(args.concurrency),
                    "SCENARIO_PHASE3_MODE": "phase2",
                    "SCENARIO_PHASE3_DATASET": str(subset),
                    "SCENARIO_PHASE3_LABEL": "static_llm",
                    "SCENARIO_PHASE3_OUTPUT": str(out_c),
                    "LLM_THINKING_OUT":
                        str(results / f"exp_{tag}_C_static_llm.thinking.json")},
            "timeout": 10800, "row": f"C static+LLM {tag}", "out": out_c,
        })

    if args.legs & {"D"}:
        out_d = results / f"exp_{tag}_D_full.json"
        steps.append({
            "name": "D", "leg": "D",
            "argv": [sys.executable, "codey_security.py", "phase3"],
            "env": {"PHASE2_INCLUDE_STRUCTURAL": "true",
                    "PHASE2_CONCURRENCY": str(args.concurrency),
                    "SCENARIO_PHASE3_MODE": "phase2",
                    "SCENARIO_PHASE3_DATASET": str(subset),
                    "SCENARIO_PHASE3_LABEL": "static_structural_llm",
                    "SCENARIO_PHASE3_OUTPUT": str(out_d),
                    "LLM_THINKING_OUT":
                        str(results / f"exp_{tag}_D_full.thinking.json")},
            "timeout": 10800, "row": f"D full {tag}", "out": out_d,
        })

    return steps, tag, summary


def print_catalog() -> int:
    print("suites:   static = A | taint = E | llm = B,C,D (+ A on the subset)")
    print(f"legs:     {', '.join(LEGS)}  (pick with --legs, default: all in suite)")
    print("datasets: --datasets name1,name2  or  --datasets all")
    print()
    print(f"{'name':22s} {'samples':>8s} {'vuln':>6s}  languages  manifest")
    for name, path in MANIFESTS.items():
        count, vulnerable, languages = manifest_info(path)
        exists = (REPO_ROOT / path).is_file()
        flag = "" if exists else "   [MISSING]"
        print(f"{name:22s} {count:8d} {vulnerable:6d}  "
              f"{','.join(languages) or '?':16s} {path}{flag}")
    print()
    print(f"LLM subset source: --llm-source {DEFAULT_LLM_SOURCE} "
          f"(any dataset name above)")
    print(f"LLM budget:        max_tokens={os.environ.get('LLM_MAX_TOKENS', '?')} "
          f"cap={os.environ.get('LLM_MAX_TOKENS_CAP', '?')} "
          f"temperature={os.environ.get('LLM_TEMPERATURE', '?')} "
          f"effort={os.environ.get('LLM_REASONING_EFFORT', 'provider default')}")
    print(f"model:             "
          f"{os.environ.get('LLM_MODEL_ID') or os.environ.get('LLM_MODEL', '?')} "
          f"base_url={os.environ.get('LLM_BASE_URL', '?')}")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--list", action="store_true",
                        help="print every suite, leg and dataset with its "
                             "sample counts, then exit")
    parser.add_argument("--dry-run", action="store_true",
                        help="print the steps that would run, execute nothing")
    parser.add_argument("--suite", default="all",
                        help="comma list of: static,taint,llm (default: all)")
    parser.add_argument("--legs", default="all",
                        help="comma list of legs inside the suite: "
                             "A,B,C,D,E (default: all of them)")
    parser.add_argument("--datasets", default="all",
                        help="comma list of manifest short names or 'all'")
    parser.add_argument("--llm-source", default=DEFAULT_LLM_SOURCE,
                        help=f"dataset the LLM subset is cut from "
                             f"(default: {DEFAULT_LLM_SOURCE}; use "
                             f"vulnllm_r_python to judge the Python set)")
    parser.add_argument("--llm-limit", type=int, default=60,
                        help="samples for the LLM subset manifest (default: 60)")
    parser.add_argument("--concurrency", type=int, default=4,
                        help="parallel LLM calls for experiment B (default: 4)")
    parser.add_argument("--llm-timeout", type=float, default=600,
                        help="per-request timeout for every LLM leg in seconds "
                             "(default: 600; the .env default of 300 was too "
                             "short for the reasoning models and turned slow "
                             "samples into ERROR records)")
    parser.add_argument("--results-dir", default="results",
                        help="where to write reports (default: results)")
    parser.add_argument("--model", default=None,
                        help="LLM model id for the B/C/D legs "
                             "(sets LLM_MODEL_ID for every child step, e.g. "
                             "--model jev-1.13-free). Default: .env value.")
    parser.add_argument("--tag", default=None,
                        help="name used for the LLM output files "
                             "(default: <llm-source>_<llm-limit>). Set it to "
                             "keep runs of a second model side by side instead "
                             "of overwriting -- and, with --resume, mixing them "
                             "into one predictions file.")
    args = parser.parse_args(argv)

    if args.list:
        return print_catalog()

    if args.model:
        # Exported, not just passed along: codey_security.py children read
        # LLM_MODEL_ID from the environment via env_config.
        os.environ["LLM_MODEL_ID"] = args.model
        os.environ["LLM_MODEL"] = args.model
        log(f"LLM model override: {args.model}")

    suite = {s.strip() for s in args.suite.split(",") if s.strip()}
    unknown_suites = sorted(s for s in suite if s not in SUITES and s != "all")
    if unknown_suites:
        print(f"error: unknown suite(s) {unknown_suites}; choose from {SUITES}")
        return 2
    if args.legs.strip().lower() == "all":
        args.legs = set(LEGS)
    else:
        args.legs = {p.strip().upper() for p in args.legs.split(",") if p.strip()}
        bad = sorted(args.legs - set(LEGS))
        if bad:
            print(f"error: unknown leg(s) {bad}; choose from {LEGS}")
            return 2

    names = list(MANIFESTS) if args.datasets == "all" else [
        n.strip() for n in args.datasets.split(",") if n.strip()
    ]
    for name in names:
        if name not in MANIFESTS:
            print(f"error: unknown dataset {name!r}; choose from {sorted(MANIFESTS)}")
            return 2

    results = Path(args.results_dir)
    summary: List[str] = [f"suite={args.suite} legs={','.join(sorted(args.legs))} "
                          f"datasets={','.join(names)}"]
    summary.append(
        "model="
        + (os.environ.get("LLM_MODEL_ID") or os.environ.get("LLM_MODEL", "?"))
        + f" base_url={os.environ.get('LLM_BASE_URL', '?')} "
        f"tag={args.tag or f'{args.llm_source}_{args.llm_limit}'}"
    )
    failures = 0

    steps: List[dict] = []
    if ("all" in suite or "static" in suite) and args.legs & {"A"}:
        steps += build_static_steps(names, results)
    if ("all" in suite or "taint" in suite) and args.legs & {"E"}:
        steps += build_taint_steps(names, results)

    llm_planned = "all" in suite or "llm" in suite
    if llm_planned and args.legs & {"A", "B", "C", "D"}:
        # Every LLM leg inherits one timeout: a reasoning model routinely needs
        # more than the .env default of 300s, and a timed-out sample is scored
        # as an error (a false negative) rather than as a judgement.
        os.environ["LLM_TIMEOUT"] = str(args.llm_timeout)
        os.environ.setdefault("LLM_MAX_ATTEMPTS", "2")
        # Benchmarks are long: the framed reasoning box drowns the progress
        # lines. Set LLM_THINKING_PRINT=full (or short) to watch it anyway;
        # the full trace is written to the .thinking.json sidecar regardless.
        os.environ.setdefault("LLM_THINKING_PRINT", "off")
        # The legs only agree on config if they read the same budget. The cap
        # silently decides whether a long Scanner reply survives, so record
        # what each leg will inherit: a .env edited mid-run otherwise leaves
        # one leg on the built-in default (65536) and the others on the file.
        budget = (
            "LLM budget: "
            f"max_tokens={os.environ.get('LLM_MAX_TOKENS', '4096 default')} "
            f"cap={os.environ.get('LLM_MAX_TOKENS_CAP', '65536 default')} "
            f"temperature={os.environ.get('LLM_TEMPERATURE', 'default')} "
            f"effort={os.environ.get('LLM_REASONING_EFFORT', 'provider default')} "
            "attempts transport/timeout/total="
            f"{os.environ.get('LLM_TRANSPORT_ATTEMPTS', '4')}/"
            f"{os.environ.get('LLM_TIMEOUT_ATTEMPTS', '2')}/"
            f"{os.environ.get('LLM_MAX_ATTEMPTS', '2')}"
        )
        log(budget)
        ok_llm, probe = llm_reachable()
        log(f"LLM endpoint: {probe}")
        summary.append(f"LLM endpoint: {probe}")
        llm_steps, _, llm_summary = build_llm_steps(args, names, results, budget)
        if not ok_llm and not args.dry_run:
            # The subset and its A row are deterministic, so they still run;
            # only the steps that need the model are dropped.
            llm_steps = [s for s in llm_steps if s.get("leg") not in {"B", "C", "D"}]
            summary.append("B/C/D: SKIPPED (no LLM server; start it per README, "
                           "then re-run --suite llm)")
        elif args.dry_run and not ok_llm:
            summary.append("B/C/D: endpoint currently unreachable "
                           "(the steps below are still shown)")
        steps += llm_steps
        summary += llm_summary

    if args.dry_run:
        print("\n===== DRY RUN (nothing executed) =====")
        for step in steps:
            env = " ".join(f"{k}={v}" for k, v in (step.get("env") or {}).items())
            line = f"{step['name']}: {' '.join(step['argv'])}"
            if env:
                line += f"   [{env}]"
            print(line)
            if step.get("skip"):
                print(f"  -> skipped: {step['skip']}")
        print("===== END DRY RUN =====")
        return 0

    # A row that is printed by a later step (B is scored by B-eval) also owes
    # the earlier step's wall time, otherwise the expensive part of a leg is
    # reported as zero.
    pending_parts: Dict[str, float] = {}

    for step in steps:
        if step.get("skip"):
            summary.append(f"{step.get('row', step['name'])}: skipped "
                           f"({step['skip']})")
            log(f"{step['name']}: skipped ({step['skip']})")
            continue
        ok, elapsed, tail = run_step(step["name"], step["argv"],
                                     step.get("env"), step.get("timeout"))
        part = step.get("part_of")
        if part and not step.get("row"):
            pending_parts[part] = pending_parts.get(part, 0.0) + elapsed
            if not ok:
                failures += 1
            log(f"{step['name']}: {'ok' if ok else 'FAILED'} in {elapsed:.0f}s")
            continue
        if step.get("filter_out"):
            if not ok:
                failures += 1
                summary.append(f"{step['name']}: FAILED {tail[-1]}")
            continue
        if not ok:
            failures += 1
        if step.get("row"):
            # A row printed by a later step owes the earlier step's wall time:
            # B is scored by B-eval, and reporting only the eval step made the
            # expensive leg look like "ok (0s)".
            pending = pending_parts.pop(part, 0.0) if part else 0.0
            shown = elapsed + pending
            when = (f"{shown:.0f}s = {pending:.0f}s predict + "
                    f"{elapsed:.0f}s eval" if pending else f"{shown:.0f}s")
            row = (f"{step['row']}: {'ok' if ok else 'FAILED'} "
                   f"({when}) "
                   f"{fmt_row(read_metrics(step['out'])) if ok and step.get('out') else tail[-1]}")
            summary.append(row)
        elif step.get("summary"):
            summary.append(f"{step['summary']}: {'ok' if ok else 'FAILED'}")
        log(f"{step['name']}: {'ok' if ok else 'FAILED'} in {elapsed:.0f}s")

    print("\n===== RESULT (copy everything below) =====")
    for line in summary:
        print(line)
    print(f"failures={failures}")
    print("===== END RESULT =====")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
