#!/usr/bin/env python3
"""One-shot benchmark runner: run the whole ladder, paste back the summary.

The deterministic legs (A = static tools, E = taint evidence) always run.
The LLM legs (B = LLM-only, C = static+LLM, D = full system) run only when an
LLM endpoint answers, and only on a small subset manifest so a flaky provider
cannot burn hours: the same subset is re-scored with static tools so every
row stays comparable.

Usage (run from the repo root)::

    # Everything deterministic (no API key needed)
    python scripts/run_benchmarks.py --suite static,taint

    # Full ladder (needs the OpenCode server from the README)
    python scripts/run_benchmarks.py

    # Quick smoke: 30 LLM samples instead of 60
    python scripts/run_benchmarks.py --llm-limit 30 --concurrency 2

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
from typing import Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import env_config  # noqa: E402,F401 -- loads .env into os.environ (no override
# of already-exported vars) so every child benchmark process inherits the
# same configuration as `python codey_security.py`.

from agents.openai_compat import resolve_transport  # noqa: E402

# Short name -> (manifest, language). Keep in this order for the report.
MANIFESTS: Dict[str, tuple] = {
    "vulnllm_r_c": ("datasets/vulnllm_r_c.json", "c"),
    "vulnllm_r_c_dataflow": ("datasets/vulnllm_r_c_dataflow.json", "c"),
    "vulnllm_r_python": ("datasets/vulnllm_r_python.json", "python"),
    "vulnllm_r_repo_c": ("datasets/vulnllm_r_repo_c.json", "c"),
    "primevul": ("datasets/primevul_test_paired.json", "c"),
    "bigvul": ("datasets/bigvul_test.json", "c"),
}

# LLM legs run on this manifest (small enough to finish on a flaky endpoint).
LLM_SOURCE = "datasets/vulnllm_r_c_dataflow.json"


def log(message: str) -> None:
    print(f"[bench] {message}", flush=True)


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
    base = os.environ.get("LLM_BASE_URL", "http://127.0.0.1:4096").rstrip("/")
    transport = resolve_transport(base)
    try:
        if transport == "openai":
            request = urllib.request.Request(base.rstrip("/") + "/models")
            key = os.environ.get("LLM_API_KEY") or os.environ.get("OPENAI_API_KEY")
            if key:
                request.add_header("Authorization", f"Bearer {key}")
            with urllib.request.urlopen(request, timeout=timeout) as resp:
                body = resp.read().decode("utf-8", "replace")
            model = os.environ.get("LLM_MODEL_ID") or os.environ.get("LLM_MODEL", "")
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


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--suite", default="all",
                        help="comma list of: static,taint,llm (default: all)")
    parser.add_argument("--datasets", default="all",
                        help="comma list of manifest short names or 'all'")
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
                             "(default: llm<llm-limit>). Set it to keep runs "
                             "of a second model side by side instead of "
                             "overwriting -- and, with --resume, mixing them "
                             "into one predictions file.")
    args = parser.parse_args(argv)

    if args.model:
        # Exported, not just passed along: codey_security.py children read
        # LLM_MODEL_ID from the environment via env_config.
        os.environ["LLM_MODEL_ID"] = args.model
        os.environ["LLM_MODEL"] = args.model
        log(f"LLM model override: {args.model}")

    suite = {s.strip() for s in args.suite.split(",")}
    names = list(MANIFESTS) if args.datasets == "all" else args.datasets.split(",")
    for name in names:
        if name not in MANIFESTS:
            print(f"error: unknown dataset {name!r}; choose from {sorted(MANIFESTS)}")
            return 2
    results = Path(args.results_dir)
    summary: List[str] = [f"suite={args.suite} datasets={','.join(names)}"]
    summary.append(
        "model="
        + (os.environ.get("LLM_MODEL_ID") or os.environ.get("LLM_MODEL", "?"))
        + f" base_url={os.environ.get('LLM_BASE_URL', '?')} "
        f"tag={args.tag or f'llm{args.llm_limit}'}"
    )
    failures = 0

    # -- A: static tools only (no LLM) -------------------------------------
    if "all" in suite or "static" in suite:
        for name in names:
            manifest, _ = MANIFESTS[name]
            out = results / f"exp_{name}_static.json"
            ok, elapsed, tail = run_step(
                f"A/{name}",
                [sys.executable, "codey_security.py", "phase3"],
                env={"SCENARIO_PHASE3_MODE": "phase1",
                     "SCENARIO_PHASE3_DATASET": manifest,
                     "SCENARIO_PHASE3_OUTPUT": str(out)},
                timeout=3600,
            )
            status = "ok" if ok else "FAILED"
            if not ok:
                failures += 1
            summary.append(f"A static {name}: {status} ({elapsed:.0f}s) "
                           f"{fmt_row(read_metrics(out)) if ok else tail[-1]}")
            log(f"A/{name}: {status} in {elapsed:.0f}s")

    # -- E: taint evidence (no LLM; C only) ---------------------------------
    if "all" in suite or "taint" in suite:
        for name in names:
            manifest, language = MANIFESTS[name]
            if language != "c":
                summary.append(f"E taint {name}: skipped (no C taint table)")
                continue
            out = results / f"exp_{name}_taint.json"
            ok, elapsed, tail = run_step(
                f"E/{name}",
                [sys.executable, "scripts/eval_taint_evidence.py",
                 "--dataset", manifest, "--out", str(out)],
                timeout=3600,
            )
            status = "ok" if ok else "FAILED"
            if not ok:
                failures += 1
            summary.append(f"E taint {name}: {status} ({elapsed:.0f}s) "
                           f"{fmt_row(read_metrics(out)) if ok else tail[-1]}")
            log(f"E/{name}: {status} in {elapsed:.0f}s")

    # -- B/C/D: LLM legs on a small subset ----------------------------------
    if "all" in suite or "llm" in suite:
        # Every LLM leg inherits one timeout: a reasoning model routinely needs
        # more than the .env default of 300s, and a timed-out sample is scored
        # as an error (a false negative) rather than as a judgement.
        os.environ["LLM_TIMEOUT"] = str(args.llm_timeout)
        os.environ.setdefault("LLM_MAX_ATTEMPTS", "2")
        # Benchmarks are long: the framed reasoning box drowns the progress
        # lines. Set LLM_THINKING_PRINT=full (or short) to watch it anyway;
        # the full trace is written to the .thinking.json sidecar regardless.
        os.environ.setdefault("LLM_THINKING_PRINT", "off")
        ok_llm, probe = llm_reachable()
        log(f"LLM endpoint: {probe}")
        summary.append(f"LLM endpoint: {probe}")
        if not ok_llm:
            summary.append("B/C/D: SKIPPED (no LLM server; start it per README, then re-run --suite llm)")
        else:
            # NOTE: the subset manifest must live next to the source manifest
            # (datasets/), not in results/: sample `file` entries are stored
            # relative to the manifest's own directory, so a subset written
            # elsewhere resolves every sample to a nonexistent path.
            subset = REPO_ROOT / "datasets" / f"llm_subset_{args.llm_limit}.json"
            ok, _, tail = run_step(
                "subset",
                [sys.executable, "scripts/filter_manifest.py",
                 "--in", LLM_SOURCE, "--out", str(subset),
                 "--limit", str(args.llm_limit)],
            )
            if not ok:
                summary.append(f"subset manifest: FAILED {tail[-1]}")
                failures += 1
            else:
                tag = args.tag or f"llm{args.llm_limit}"
                # A on the same subset, so every row is comparable.
                out_a = results / f"exp_{tag}_A_static.json"
                ok, elapsed, tail = run_step(
                    "A-sub", [sys.executable, "codey_security.py", "phase3"],
                    env={"SCENARIO_PHASE3_MODE": "phase1",
                         "SCENARIO_PHASE3_DATASET": str(subset),
                         "SCENARIO_PHASE3_OUTPUT": str(out_a)},
                    timeout=3600,
                )
                summary.append(f"A static {tag}: {'ok' if ok else 'FAILED'} "
                               f"({elapsed:.0f}s) {fmt_row(read_metrics(out_a)) if ok else tail[-1]}")
                # B: LLM only.
                pred = results / f"exp_{tag}_B_llm_only.jsonl"
                b_args = [sys.executable, "scripts/run_llm_only_benchmark.py",
                          "--dataset", str(subset), "--out", str(pred),
                          "--concurrency", str(args.concurrency),
                          "--timeout", str(args.llm_timeout), "--resume"]
                if args.model:
                    b_args += ["--model", args.model]
                ok, elapsed, tail = run_step(
                    "B", b_args,
                    env={"LLM_THINKING_OUT":
                         str(results / f"exp_{tag}_B_llm_only.thinking.json")},
                    timeout=10800,
                )
                out_b = results / f"exp_{tag}_B_llm_only.json"
                be_args = [sys.executable, "scripts/evaluate_llm_only.py",
                           "--dataset", str(subset), "--predictions", str(pred),
                           "--out", str(out_b)]
                if args.model:
                    be_args += ["--model", args.model]
                ok2, _, tail2 = run_step("B-eval", be_args, timeout=600)
                good = ok and ok2
                if not good:
                    failures += 1
                summary.append(f"B llm-only {tag}: {'ok' if good else 'FAILED'} "
                               f"({elapsed:.0f}s) {fmt_row(read_metrics(out_b)) if good else (tail + tail2)[-1]}")
                # C: static findings + LLM, no structural evidence.
                out_c = results / f"exp_{tag}_C_static_llm.json"
                ok, elapsed, tail = run_step(
                    "C",
                    [sys.executable, "codey_security.py", "phase3"],
                    env={"PHASE2_INCLUDE_STRUCTURAL": "false",
                         "SCENARIO_PHASE3_MODE": "phase2",
                         "SCENARIO_PHASE3_DATASET": str(subset),
                         "SCENARIO_PHASE3_LABEL": "static_llm",
                         "SCENARIO_PHASE3_OUTPUT": str(out_c),
                         "LLM_THINKING_OUT":
                             str(results / f"exp_{tag}_C_static_llm.thinking.json")},
                    timeout=10800,
                )
                if not ok:
                    failures += 1
                summary.append(f"C static+LLM {tag}: {'ok' if ok else 'FAILED'} "
                               f"({elapsed:.0f}s) {fmt_row(read_metrics(out_c)) if ok else tail[-1]}")
                # D: static + structural evidence + LLM (proposed system).
                out_d = results / f"exp_{tag}_D_full.json"
                ok, elapsed, tail = run_step(
                    "D",
                    [sys.executable, "codey_security.py", "phase3"],
                    env={"PHASE2_INCLUDE_STRUCTURAL": "true",
                         "SCENARIO_PHASE3_MODE": "phase2",
                         "SCENARIO_PHASE3_DATASET": str(subset),
                         "SCENARIO_PHASE3_LABEL": "static_structural_llm",
                         "SCENARIO_PHASE3_OUTPUT": str(out_d),
                         "LLM_THINKING_OUT":
                             str(results / f"exp_{tag}_D_full.thinking.json")},
                    timeout=10800,
                )
                if not ok:
                    failures += 1
                summary.append(f"D full {tag}: {'ok' if ok else 'FAILED'} "
                               f"({elapsed:.0f}s) {fmt_row(read_metrics(out_d)) if ok else tail[-1]}")

    print("\n===== RESULT (copy everything below) =====")
    for line in summary:
        print(line)
    print(f"failures={failures}")
    print("===== END RESULT =====")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
