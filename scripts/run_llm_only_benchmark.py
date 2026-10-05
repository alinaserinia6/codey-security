#!/usr/bin/env python3
"""Experiment B — LLM-only baseline.

The model receives one complete source file and no static-analysis evidence,
no structural evidence and no ground-truth hints.  Every label leak (scenario
comments, scenario identifiers and the ``bad``/``good`` variant markers) is
removed with :mod:`phase2.sanitize` first, otherwise the baseline would simply
read the answer out of the file.

Each sample appends one JSON line to ``--out`` as soon as it finishes, so an
interrupted run can still be evaluated (see ``scripts/evaluate_llm_only.py``).

Usage:
    python scripts/run_llm_only_benchmark.py \
        --dataset datasets/llm_subset_20.json \
        --out results/exp_B_llm_only.jsonl \
        --concurrency 12
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from agents.security_agent import SecurityAgent  # noqa: E402
from agents.openai_compat import sampling_settings  # noqa: E402
from analyzers.normalize import clamp_confidence, safe_cwe_list  # noqa: E402
from agents import thinking_log  # noqa: E402
from env_config import get_config  # noqa: E402  (loads .env, like every other entry point)
from phase2.sanitize import sanitize_source  # noqa: E402
from phase3.dataset import GroundTruthDataset  # noqa: E402

LLM_ONLY_PROMPT = """
You are a standalone source-code vulnerability detector.

You will receive one complete source file as JSON: the language and the full
file text. Nothing else is known about the file: no static-analysis findings,
no compiler output, no caller context.

Rules for the input:
- The file text is inlined in this message. You have no file-system, shell or
  search tools in this session: never try to open, locate, list or read a file,
  and never claim a file is missing — everything you get is what exists.
- The "file" field is only a name for reference; it is not a path you can open.

Decide whether the file contains at least one real, demonstrable security
vulnerability that a reviewer would file as a defect (memory-safety error,
integer overflow/truncation with a security consequence, injection, ...).
Style issues, defensive-coding suggestions and theoretical weaknesses with no
concrete triggering path are NOT vulnerabilities.

Rules:
1. Use only the supplied file text. Never invent code.
2. Report the single most specific CWE for the primary issue.
3. Be conservative: if the file is benign or you cannot point at a concrete
   defective statement, return REJECTED.
4. Return ONLY one valid JSON object, no Markdown, no prose, no fences.

JSON schema (the only accepted output):
{
  "decision": "CONFIRMED|REJECTED|UNCERTAIN",
  "confidence": 0.0,
  "rationale": "short technical explanation naming the defective statement",
  "evidence": ["line numbers or statements"],
  "missing_evidence": ["what you would need to be sure"],
  "source_location": "file:line or null",
  "cwe": ["CWE-..."],
  "severity": "LOW|MEDIUM|HIGH|CRITICAL|UNKNOWN"
}

CONFIRMED means the file contains a vulnerability, REJECTED means it does not.

Keep it short: `rationale` is one sentence naming the defective statement,
`evidence` and `missing_evidence` hold at most three bare items each, and no
field quotes the file back — the whole file was sent once already.
""".strip()

_LANGUAGE_BY_EXT = {
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cp": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hh": "cpp",
    ".hpp": "cpp",
    ".hxx": "cpp",
    ".py": "python",
    ".pyw": "python",
}


def _language(path: str) -> str:
    ext = Path(path).suffix.lower()
    return _LANGUAGE_BY_EXT.get(ext, "unknown")


def thinking_out_path(out: str, explicit: "str | None" = None) -> str:
    """Sidecar reasoning trace for one predictions file.

    ``results/exp_B.jsonl`` -> ``results/exp_B.thinking.json``, so the trace
    always sits next to the run it documents and ``--resume`` keeps appending
    to the same file.
    """
    if explicit:
        return explicit
    return str(Path(out).with_suffix("")) + ".thinking.json"


def _line_from_location(location) -> "int | None":
    if not isinstance(location, str) or ":" not in location:
        return None
    tail = location.rsplit(":", 1)[-1].strip()
    try:
        value = int(tail)
    except ValueError:
        return None
    return value if value > 0 else None


async def _judge(agent: SecurityAgent, sem: asyncio.Semaphore, sample: dict) -> dict:
    path = Path(sample["file"])
    record = {
        "sample_id": sample["sample_id"],
        "file": str(path),
        "language": _language(str(path)),
        "decision": "ERROR",
        "cwe": [],
        "line": None,
        "confidence": 0.0,
        "severity": "UNKNOWN",
        "rationale": "",
        "error": None,
        "elapsed": 0.0,
        "model": agent.model_id,
        "base_url": agent.base_url,
    }
    started = time.monotonic()  # only used on the read-failure path below
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        record["error"] = f"read failed: {exc}"
        record["elapsed"] = round(time.monotonic() - started, 2)
        return record

    packet = {
        "language": record["language"],
        "file": "sample" + path.suffix,
        "source": sanitize_source(text, record["language"], path=str(path)),
    }
    async with sem:
        # Timed from here, not from the start of _judge: with 4 workers the
        # queue wait of the last samples dwarfs the request itself, and
        # `elapsed` is summed into the evaluation's request-seconds figure.
        started = time.monotonic()
        try:
            # The scope tells the transport which sample this reply belongs to,
            # so the sidecar thinking log ends up keyed by sample_id + real path
            # rather than by the neutral "sample.c" name inside the packet.
            with thinking_log.scope(
                id=sample["sample_id"], file=str(path), role="llm_only"
            ):
                value = await agent.analyze(packet, system_prompt=LLM_ONLY_PROMPT)
        except Exception as exc:  # noqa: BLE001 - one bad LLM reply must not stop the run
            record["error"] = f"{type(exc).__name__}: {exc}"
            record["elapsed"] = round(time.monotonic() - started, 2)
            return record

        # The model reply is untrusted: a non-dict, a numeric confidence as
        # text ("high"), or a line as a string must degrade to an ERROR
        # record, never to an exception that kills the whole benchmark.
        try:
            if not isinstance(value, dict):
                raise ValueError(
                    f"expected a JSON object, got {type(value).__name__}"
                )
            record["decision"] = str(value.get("decision", "UNCERTAIN")).upper()
            if record["decision"] not in {"CONFIRMED", "REJECTED", "UNCERTAIN"}:
                record["decision"] = "UNCERTAIN"
            record["cwe"] = safe_cwe_list(value.get("cwe"))
            record["line"] = _line_from_location(value.get("source_location"))
            record["confidence"] = clamp_confidence(value.get("confidence"))
            record["severity"] = str(value.get("severity") or "UNKNOWN").upper()
            record["rationale"] = str(value.get("rationale") or "")
        except Exception as exc:  # noqa: BLE001
            record["decision"] = "ERROR"
            record["error"] = f"unparsable model reply: {type(exc).__name__}: {exc}"
        record["elapsed"] = round(time.monotonic() - started, 2)
        return record


async def run(args) -> None:
    # Resolve paths through the dataset loader so relative manifests behave
    # exactly as they do in experiments A/C/D.
    dataset = GroundTruthDataset.from_json(args.dataset)
    samples = [
        {"sample_id": s.sample_id, "file": str(dataset.resolve_file(s))}
        for s in dataset
    ]
    if args.shuffle_seed is not None:
        import random

        random.Random(args.shuffle_seed).shuffle(samples)
        print(f"Shuffled dataset with seed {args.shuffle_seed}")
    if args.limit:
        samples = samples[: args.limit]
        print(f"Limited to {len(samples)} samples")

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # Sidecar reasoning trace: one JSON file, one entry per judged sample, so
    # "what did the model actually see and think?" survives the run.
    os.environ.setdefault(
        thinking_log.ENV_OUT, thinking_out_path(str(out_path), args.thinking_out)
    )
    # Quiet terminal: the progress lines are the useful output here. Export
    # LLM_THINKING_PRINT=short/full to watch the reasoning live as well.
    os.environ.setdefault("LLM_THINKING_PRINT", "off")

    done: set[str] = set()
    if args.resume and out_path.exists():
        for line in out_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            sample_id = record.get("sample_id")
            if not sample_id or record.get("decision") == "ERROR":
                # A failed sample must be retried, not treated as finished.
                continue
            done.add(str(sample_id))
        print(f"Resuming: {len(done)} samples already evaluated")

    todo = [s for s in samples if s["sample_id"] not in done]
    print(f"{len(todo)} samples to judge ({len(samples)} total)")
    print(f"Thinking log: {os.environ.get(thinking_log.ENV_OUT, '(disabled)')}")

    cfg = get_config()
    agent = SecurityAgent(
        base_url=args.base_url or cfg.llm_base_url,
        model_id=args.model or cfg.llm_model_id,
        provider_id=cfg.llm_provider_id,
        mode=cfg.llm_mode,
        timeout=args.timeout or cfg.llm_timeout,
        reuse_session=cfg.llm_reuse_session,
    )
    print(
        f"Model: {agent.model_id}  transport: {agent.transport}  "
        f"base_url: {agent.base_url}  timeout: {agent.timeout}s"
    )
    settings = sampling_settings()
    print(
        f"Sampling: temperature={settings['temperature']!r}  "
        f"reasoning_effort={settings['reasoning_effort']!r}  "
        f"concurrency={args.concurrency}"
    )
    if agent.transport == "openai":
        print(
            "  api key: "
            + ("set" if os.environ.get("LLM_API_KEY") else "NOT SET (LLM_API_KEY)")
        )
    sem = asyncio.Semaphore(args.concurrency)
    reporter_lock = asyncio.Lock()
    state = {"i": 0, "errors": 0, "confirmed": 0, "start": time.monotonic()}

    out_file = out_path.open("a", encoding="utf-8")

    async def one(sample: dict) -> None:
        # Console only, never written to the JSONL: shows which file is about
        # to be judged (and whether it even exists) before the LLM call.
        async with reporter_lock:
            missing = "" if Path(sample.get("file", "")).is_file() else "  MISSING!"
            print(f"judge {sample.get('sample_id', '<unknown>')}\n"
                  f"  file {sample.get('file', '')}{missing}", flush=True)
        try:
            record = await _judge(agent, sem, sample)
        except Exception as exc:  # noqa: BLE001 - defensive; _judge already isolates
            record = {
                "sample_id": sample.get("sample_id", "<unknown>"),
                "file": str(sample.get("file", "")),
                "language": "unknown",
                "decision": "ERROR",
                "cwe": [],
                "line": None,
                "confidence": 0.0,
                "severity": "UNKNOWN",
                "rationale": "",
                "error": f"harness failure: {type(exc).__name__}: {exc}",
                "elapsed": 0.0,
                "model": agent.model_id,
                "base_url": agent.base_url,
            }
        # The configuration a verdict was produced under travels with the
        # verdict: a JSONL that does not record its temperature cannot later
        # support a claim about non-determinism.  Read from the transport, not
        # from the environment, so a field dropped mid-run is recorded as
        # dropped rather than as sent.
        compat = getattr(agent, "_openai", None)
        effective = compat.effective_settings() if compat is not None else settings
        record["temperature"] = effective.get("temperature")
        record["reasoning_effort"] = effective.get("reasoning_effort")
        if effective.get("reasoning_effort_dropped"):
            record["reasoning_effort_dropped"] = True
        record["concurrency"] = args.concurrency
        async with reporter_lock:
            out_file.flush()
            state["i"] += 1
            if record["error"]:
                state["errors"] += 1
            if record["decision"] == "CONFIRMED":
                state["confirmed"] += 1
            i = state["i"]
            elapsed = time.monotonic() - state["start"]
            rate = i / elapsed if elapsed else 0.0
            eta = (len(todo) - i) / rate if rate else float("inf")
            print(
                f"[{i:>5}/{len(todo)}] {100.0 * i / max(len(todo), 1):5.1f}%  "
                f"{record['sample_id'][:52]:<52}  "
                f"elapsed {elapsed:7.1f}s  eta {eta:7.1f}s  "
                f"C={state['confirmed']} err={state['errors']}",
                flush=True,
            )

    try:
        await asyncio.gather(*(one(s) for s in todo), return_exceptions=True)
    finally:
        out_file.close()

    print(
        f"Done: {state['i']} judged, {state['confirmed']} CONFIRMED, "
        f"{state['errors']} errors, {time.monotonic() - state['start']:.1f}s"
    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dataset", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--concurrency", type=int, default=12)
    p.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="per-request timeout in seconds (default: LLM_TIMEOUT)",
    )
    p.add_argument("--model", default=None, help="override LLM_MODEL_ID for this run")
    p.add_argument("--base-url", default=None, help="override LLM_BASE_URL for this run")
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--shuffle-seed", type=int, default=None)
    p.add_argument(
        "--thinking-out",
        default=None,
        help="JSON file that collects every model reasoning trace for this run "
             "(default: <out>.thinking.json; honours LLM_THINKING_OUT)",
    )
    p.add_argument("--resume", action="store_true")
    return p


def validate_args(args) -> None:
    """Fail fast on knobs that would otherwise hang or silently mis-run.

    ``--concurrency 0`` deadlocks the semaphore, a negative ``--limit``
    slices from the end of the dataset, and a non-positive ``--timeout``
    fails every request immediately. All three come from typos, so they
    are hard errors, not clamps.
    """
    if args.concurrency < 1:
        raise ValueError(f"--concurrency must be >= 1, got {args.concurrency}")
    if args.limit < 0:
        raise ValueError(f"--limit must be >= 0, got {args.limit}")
    if args.timeout is not None and not args.timeout > 0:
        raise ValueError(f"--timeout must be > 0, got {args.timeout}")


if __name__ == "__main__":
    _args = build_parser().parse_args()
    try:
        validate_args(_args)
    except ValueError as exc:
        build_parser().error(str(exc))
    asyncio.run(run(_args))
