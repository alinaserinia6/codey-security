#!/usr/bin/env python3
"""Group-safe train/test split for Codey-Security Juliet manifests.

Merges one or more input manifests, deduplicates by sample_id, optionally
filters to a set of CWEs, optionally caps samples per group and per CWE,
then splits by group_id so all variants of a scenario stay on one side of
the split.

Order of operations
-------------------
1. Merge all input manifests, dedup by sample_id, absolutize file paths.
2. Apply --per-group-limit (if set) to the merged pool.
3. Split the merged pool into train/test by group_id.
4. Apply --cwe filter (if set) to each side.
5. Apply --per-cwe-limit (if set) to each side.

Because the split is computed in step 3 on the *full* pool, the same
--seed and --test-ratio produce the same test groups regardless of which
CWEs you request in step 4 (adding a CWE adds groups to both sides, it does
not reshuffle them).

Usage
-----
    # Basic split
    python scripts/split_juliet_manifest.py \\
        datasets/juliet_hf_train.json \\
        datasets/juliet_hf_test.json \\
        --train-out datasets/juliet_train.json \\
        --test-out  datasets/juliet_test.json \\
        --test-ratio 0.2 --seed 42

    # Filter to specific CWEs
    python scripts/split_juliet_manifest.py \\
        datasets/juliet_hf_train.json \\
        datasets/juliet_hf_test.json \\
        --cwe CWE-78 --cwe CWE-121 --cwe CWE-134 \\
        --train-out datasets/juliet_train.json \\
        --test-out  datasets/juliet_test.json

    # Cap representation: at most 200 samples per CWE per side
    python scripts/split_juliet_manifest.py \\
        datasets/juliet_hf_train.json \\
        datasets/juliet_hf_test.json \\
        --cwe CWE-78 --cwe CWE-121 --cwe CWE-134 \\
        --per-cwe-limit 200 \\
        --train-out datasets/juliet_train.json \\
        --test-out  datasets/juliet_test.json

    # Cap both per group and per CWE
    python scripts/split_juliet_manifest.py \\
        datasets/juliet_hf_train.json \\
        datasets/juliet_hf_test.json \\
        --per-group-limit 4 \\
        --per-cwe-limit 200 \\
        --train-out datasets/juliet_train.json \\
        --test-out  datasets/juliet_test.json
"""
from __future__ import annotations

import argparse
import json
import random
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple


# ---------------------------------------------------------------------------
# CWE normalization
# ---------------------------------------------------------------------------
def _normalize_cwe(token: str) -> str:
    """CWE120, cwe-120, CWE-120 -> 'CWE-120'."""
    cleaned = token.strip().upper().replace("CWE", "CWE-").replace("--", "-")
    m = re.match(r"^CWE-(\d+)$", cleaned)
    if not m:
        raise ValueError(
            f"Unrecognized CWE token: {token!r}. "
            "Use forms like 'CWE-120' or 'CWE120'."
        )
    return f"CWE-{int(m.group(1))}"


def _normalize_cwe_set(tokens: Optional[Iterable[str]]) -> Optional[Set[str]]:
    if not tokens:
        return None
    return {_normalize_cwe(t) for t in tokens}


# ---------------------------------------------------------------------------
# Manifest I/O
# ---------------------------------------------------------------------------
def _load(path: Path) -> Dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or "samples" not in payload:
        raise ValueError(f"{path}: not a valid manifest (missing 'samples')")
    return payload


def _merge(manifests: Sequence[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], int]:
    """Flatten manifests into one list, dedup by sample_id, absolutize paths."""
    merged: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    dropped = 0

    for m in manifests:
        root_value = m.get("dataset", {}).get("root")
        root = Path(root_value).resolve() if root_value else None
        for s in m["samples"]:
            sid = s.get("sample_id")
            if not sid:
                raise ValueError("Manifest entry missing 'sample_id'")
            if sid in seen:
                dropped += 1
                continue
            seen.add(sid)

            entry = dict(s)
            fpath = Path(entry["file"])
            if not fpath.is_absolute() and root is not None:
                entry["file"] = str((root / fpath).resolve())
            merged.append(entry)

    return merged, dropped


# ---------------------------------------------------------------------------
# Filtering and limiting
# ---------------------------------------------------------------------------
def _filter_cwe(
    samples: List[Dict[str, Any]], wanted: Set[str]
) -> List[Dict[str, Any]]:
    """Keep samples whose cwe list intersects `wanted`."""
    kept: List[Dict[str, Any]] = []
    for s in samples:
        sample_cwes = {c.upper() for c in s.get("cwe", [])}
        if sample_cwes & wanted:
            kept.append(s)
    return kept


def _limit_per_group(
    samples: List[Dict[str, Any]], limit: int
) -> List[Dict[str, Any]]:
    """Keep at most `limit` samples per group, deterministically.

    One `bad` is always kept if present; remaining slots are filled with the
    lexicographically-first `good` samples so the selection is stable.
    """
    by_group: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for s in samples:
        by_group[s["group_id"]].append(s)

    kept: List[Dict[str, Any]] = []
    for group in by_group.values():
        group.sort(key=lambda s: (not s["vulnerable"], s["sample_id"]))
        kept.extend(group[:limit])
    return kept


def _limit_per_cwe(
    samples: List[Dict[str, Any]], limit: int
) -> List[Dict[str, Any]]:
    """Keep at most `limit` samples per CWE.

    A sample with multiple CWEs can be selected by any of its CWE quotas;
    the union of all selected samples is returned. Samples with no CWEs are
    passed through unchanged (they cannot be evaluated per-CWE).

    Deterministic: for each CWE, bad samples come first, then lexicographic
    by sample_id. The output preserves the input order.
    """
    by_cwe: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for s in samples:
        for cwe in s.get("cwe", []):
            by_cwe[cwe.upper()].append(s)

    kept_ids: Set[str] = set()
    for bucket in by_cwe.values():
        bucket.sort(key=lambda s: (not s["vulnerable"], s["sample_id"]))
        for s in bucket[:limit]:
            kept_ids.add(s["sample_id"])

    return [
        s for s in samples
        if s["sample_id"] in kept_ids or not s.get("cwe")
    ]


# ---------------------------------------------------------------------------
# Split
# ---------------------------------------------------------------------------
def _group_split(
    samples: List[Dict[str, Any]],
    *,
    test_ratio: float,
    seed: int,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, int]]:
    by_group: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for s in samples:
        by_group[s["group_id"]].append(s)

    groups = sorted(by_group.keys())
    rng = random.Random(seed)
    rng.shuffle(groups)

    n_test = max(1, int(round(len(groups) * test_ratio)))
    test_groups = set(groups[:n_test])
    train_groups = set(groups[n_test:])

    train_samples = [s for s in samples if s["group_id"] in train_groups]
    test_samples = [s for s in samples if s["group_id"] in test_groups]

    stats = {
        "total_groups": len(groups),
        "train_groups": len(train_groups),
        "test_groups": len(test_groups),
    }
    return train_samples, test_samples, stats


# ---------------------------------------------------------------------------
# Summary + output
# ---------------------------------------------------------------------------
def _summary(samples: List[Dict[str, Any]]) -> Dict[str, int]:
    vulnerable = sum(1 for s in samples if s["vulnerable"])
    return {
        "sample_count": len(samples),
        "vulnerable_count": vulnerable,
        "benign_count": len(samples) - vulnerable,
    }


def _per_cwe_counts(samples: List[Dict[str, Any]]) -> Dict[str, int]:
    counter: Counter = Counter()
    for s in samples:
        for cwe in s.get("cwe", []):
            counter[cwe.upper()] += 1
    return dict(sorted(counter.items()))


def _write(
    samples: List[Dict[str, Any]],
    *,
    name: str,
    out_path: Path,
    seed: int,
    test_ratio: float,
    cwe_filter: Optional[Set[str]],
    per_group_limit: Optional[int],
    per_cwe_limit: Optional[int],
    source_manifests: Sequence[str],
) -> None:
    summary = _summary(samples)
    payload = {
        "dataset": {
            "name": name,
            "root": None,               # files are absolute in the output
            "sample_count": summary["sample_count"],
            "vulnerable_count": summary["vulnerable_count"],
            "benign_count": summary["benign_count"],
            "split": {
                "method": "group_safe",
                "seed": seed,
                "test_ratio": test_ratio,
                "cwe_filter": sorted(cwe_filter) if cwe_filter else None,
                "per_group_limit": per_group_limit,
                "per_cwe_limit": per_cwe_limit,
                "source_manifests": list(source_manifests),
            },
            "per_cwe": _per_cwe_counts(samples),
        },
        "samples": samples,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(
        f"{name}: {summary['sample_count']} samples "
        f"({summary['vulnerable_count']} vulnerable / "
        f"{summary['benign_count']} benign) -> {out_path}"
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "manifests",
        nargs="+",
        help="Input manifest JSON files.",
    )
    p.add_argument(
        "--train-out", required=True,
        help="Output path for the train manifest.",
    )
    p.add_argument(
        "--test-out", required=True,
        help="Output path for the test manifest.",
    )
    p.add_argument(
        "--cwe",
        action="append",
        default=None,
        metavar="CWE",
        help=(
            "Keep only these CWEs. Repeatable. Accepts 'CWE-120' or 'CWE120'. "
            "If omitted, all CWEs in the input pool are kept."
        ),
    )
    p.add_argument(
        "--test-ratio", type=float, default=0.2,
        help="Fraction of groups assigned to the test split (default: 0.2).",
    )
    p.add_argument(
        "--seed", type=int, default=42,
        help="Random seed for group shuffling (default: 42).",
    )
    p.add_argument(
        "--per-group-limit", type=int, default=None,
        help=(
            "Keep at most N samples per group (deterministic, bad-first). "
            "Applied to the merged pool before the split."
        ),
    )
    p.add_argument(
        "--per-cwe-limit", type=int, default=None,
        help=(
            "Keep at most N samples per CWE, applied to each side "
            "independently after the split. Deterministic, bad-first. "
            "Use this to bound the size of very large CWE buckets."
        ),
    )
    return p.parse_args()


def main() -> None:
    args = _parse_args()

    if not 0.0 < args.test_ratio < 1.0:
        raise SystemExit("--test-ratio must be strictly between 0 and 1")
    if args.per_group_limit is not None and args.per_group_limit < 1:
        raise SystemExit("--per-group-limit must be >= 1")
    if args.per_cwe_limit is not None and args.per_cwe_limit < 1:
        raise SystemExit("--per-cwe-limit must be >= 1")

    # --- 1. load + merge -------------------------------------------------
    manifest_paths = [Path(m) for m in args.manifests]
    for mp in manifest_paths:
        if not mp.exists():
            raise SystemExit(f"Manifest does not exist: {mp}")
    manifests = [_load(mp) for mp in manifest_paths]

    samples, dropped = _merge(manifests)
    print(f"merged: {len(samples)} unique samples ({dropped} duplicates dropped)")
    if not samples:
        raise SystemExit("No samples after merge. Check the input manifests.")

    # --- 2. per-group limit (full pool) ----------------------------------
    if args.per_group_limit is not None:
        before = len(samples)
        samples = _limit_per_group(samples, args.per_group_limit)
        print(
            f"per-group limit={args.per_group_limit}: "
            f"{before} -> {len(samples)} samples"
        )

    # --- 3. group-safe split on the full pool ----------------------------
    train, test, stats = _group_split(
        samples, test_ratio=args.test_ratio, seed=args.seed
    )
    print(
        f"groups: {stats['total_groups']} total -> "
        f"{stats['train_groups']} train / {stats['test_groups']} test"
    )

    # --- 4. CWE filter (per side) ----------------------------------------
    cwe_filter = _normalize_cwe_set(args.cwe)
    if cwe_filter is not None:
        train_before, test_before = len(train), len(test)
        train = _filter_cwe(train, cwe_filter)
        test = _filter_cwe(test, cwe_filter)
        print(
            f"cwe filter {sorted(cwe_filter)}: "
            f"train {train_before} -> {len(train)}, "
            f"test {test_before} -> {len(test)}"
        )
        if not train or not test:
            raise SystemExit(
                "CWE filter removed every sample on at least one side of the "
                "split. Check the 'per_cwe' block of the input manifests."
            )

    # --- 5. per-CWE limit (per side) -------------------------------------
    if args.per_cwe_limit is not None:
        train_before, test_before = len(train), len(test)
        train = _limit_per_cwe(train, args.per_cwe_limit)
        test = _limit_per_cwe(test, args.per_cwe_limit)
        print(
            f"per-cwe limit={args.per_cwe_limit}: "
            f"train {train_before} -> {len(train)}, "
            f"test {test_before} -> {len(test)}"
        )
        # Show the resulting per-CWE distribution so the user can spot
        # any bucket that came in below the limit (i.e. the whole bucket).
        print(f"  train per-cwe: {_per_cwe_counts(train)}")
        print(f"  test  per-cwe: {_per_cwe_counts(test)}")

    # --- 6. leakage guarantee --------------------------------------------
    train_gids = {s["group_id"] for s in train}
    test_gids = {s["group_id"] for s in test}
    overlap = train_gids & test_gids
    if overlap:
        raise RuntimeError(
            f"Group leakage detected: {len(overlap)} groups in both splits. "
            f"Examples: {sorted(overlap)[:5]}"
        )
    print(
        f"leakage check: 0 overlapping groups "
        f"(train={len(train_gids)}, test={len(test_gids)})"
    )

    # --- 7. write --------------------------------------------------------
    source_names = [str(mp) for mp in manifest_paths]
    _write(
        train,
        name="juliet-group-safe-train",
        out_path=Path(args.train_out),
        seed=args.seed,
        test_ratio=args.test_ratio,
        cwe_filter=cwe_filter,
        per_group_limit=args.per_group_limit,
        per_cwe_limit=args.per_cwe_limit,
        source_manifests=source_names,
    )
    _write(
        test,
        name="juliet-group-safe-test",
        out_path=Path(args.test_out),
        seed=args.seed,
        test_ratio=args.test_ratio,
        cwe_filter=cwe_filter,
        per_group_limit=args.per_group_limit,
        per_cwe_limit=args.per_cwe_limit,
        source_manifests=source_names,
    )


if __name__ == "__main__":
    main()
