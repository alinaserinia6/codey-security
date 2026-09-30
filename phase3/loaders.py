"""Converters from public labelled corpora into the Phase 3 manifest format.

Every benchmark in the proposal is a different format, and three of them are
function-level corpora where the "file" does not exist on disk. These loaders
turn each into the single ``GroundTruthDataset`` manifest that
``scripts/eval_taint_evidence.py`` and the Phase 3 runner already read, so the
same measurement code runs over all of them.

Two things this module is careful about:

* **Labels are never guessed.** SARD in particular encodes its label in a
  directory convention that differs between distributions, so the convention is
  a parameter and anything unrecognised raises rather than being silently
  treated as benign. A benchmark harness that quietly mislabels half a corpus
  produces numbers that look like results and are not.
* **Known label noise is recorded, not hidden.** Devign and Big-Vul labels come
  from historical commits and vulnerability reports, not from re-audit, and are
  known to be noisy. The manifest says so, so a number computed from them is
  read with the right caveat.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

CWE_DIR_RE = re.compile(r"CWE[_-]?(\d+)", re.IGNORECASE)
LANGUAGE_BY_SUFFIX = {
    ".c": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".c++": "cpp",
    ".h": "c",
    ".hpp": "cpp",
    ".py": "python",
}

# Default name markers, overridable because SARD distributions differ. These
# are the conventions used by the SARD/ NIST SARD releases that name test cases
# by directory.
SARD_SAFE_DIRS = frozenset({"good", "safe", "benign", "fixed"})
SARD_VULN_DIRS = frozenset({"vulnerable", "bad", "insecure", "unsafe"})


class LoaderError(RuntimeError):
    """The corpus layout is not the one the loader was told to expect."""


def _canonical_cwe(digits: str) -> str:
    """``089`` -> ``CWE-89``.

    SARD and Juliet both use zero-padded CWE numbers in their directory names.
    Left as-is, the same weakness would be counted as two different classes in a
    per-CWE breakdown depending on which corpus the sample came from.
    """
    return f"CWE-{digits.lstrip('0') or '0'}"


def _cwe_from_path(path: Path, root: Path) -> List[str]:
    try:
        relative = path.relative_to(root)
    except ValueError:
        relative = path
    found = CWE_DIR_RE.findall(str(relative))
    # Preserve order but drop repeats, so `CWE_120/sard/sard120.c` yields one id.
    seen: List[str] = []
    for digits in found:
        cwe = _canonical_cwe(digits)
        if cwe not in seen:
            seen.append(cwe)
    return seen


def _has_marker(parts: Iterable[str], markers: Iterable[str]) -> bool:
    """Whether any path part carries one of the marker words.

    SARD names directories like ``CWE_089__sqli`` or ``CWE_120_unsafe`` as well
    as bare ``safe``, so the marker is matched as a word inside a part rather
    than as the whole part.
    """
    for part in parts:
        for token in re.split(r"[^A-Za-z]+", part):
            if token.lower() in markers:
                return True
    return False


def _language_of(path: Path) -> Optional[str]:
    return LANGUAGE_BY_SUFFIX.get(path.suffix.lower())


def _digest(samples: Sequence[Dict[str, Any]]) -> str:
    """A short fingerprint of the sample ids, so a manifest can be identified."""
    import hashlib

    joined = "\n".join(sorted(str(s.get("sample_id", "")) for s in samples))
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:16]


# -- SARD ------------------------------------------------------------------


@dataclass
class SardOptions:
    """How to read a SARD release.

    ``label_from`` selects the rule: ``"directory"`` trusts the containing
    directory name, ``"metadata"`` requires a ``metadata.csv`` in each test-case
    directory. Anything the rule cannot classify is an error, not a benign
    sample.

    Some SARD distributions put the vulnerable test case directly in the CWE
    directory and every benign case in a ``good``/``safe`` subdirectory, so the
    CWE directory itself implies "vulnerable". That is a real convention but it
    is not universal, so it is opt-in through ``assume_vulnerable`` rather than
    the default: guessing it wrong would label every benign case as vulnerable
    and quietly invert a benchmark's precision.
    """

    label_from: str = "directory"
    safe_dirs: frozenset = SARD_SAFE_DIRS
    vulnerable_dirs: frozenset = SARD_VULN_DIRS
    extensions: Sequence[str] = (".c", ".cpp", ".cc", ".cxx", ".py")
    # Column names tried, in order, when reading a metadata table.
    safe_columns: Sequence[str] = ("Type", "type", "True_Type", "true_type")
    vulnerable_values: Sequence[str] = ("vulnerable", "bad", "insecure", "true", "1")
    assume_vulnerable: bool = False


def load_sard(
    root: str | Path,
    options: Optional[SardOptions] = None,
    *,
    max_samples: Optional[int] = None,
) -> Dict[str, Any]:
    """Build a manifest for a SARD C or Python release.

    Each source file becomes one sample, labelled from the directory that
    contains it.
    """
    options = options or SardOptions()
    root = Path(root).resolve()
    if not root.is_dir():
        raise LoaderError(f"SARD root does not exist: {root}")
    if options.label_from not in ("directory", "metadata"):
        raise LoaderError(f"unknown label_from: {options.label_from!r}")

    samples: List[Dict[str, Any]] = []
    unclassified: List[str] = []

    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in options.extensions:
            continue
        language = _language_of(path)
        if language is None:
            continue
        if options.label_from == "metadata":
            label = _sard_label_from_metadata(path, options)
        else:
            label = _sard_label_from_directory(path, options, root)
        if label is None:
            unclassified.append(str(path.relative_to(root)))
            continue
        samples.append(
            {
                "sample_id": str(path.relative_to(root)),
                "file": str(path),
                "vulnerable": label,
                "cwe": _cwe_from_path(path, root),
                "language": language,
                "variant": "bad" if label else "good",
                "description": f"SARD test case {path.name}",
            }
        )
        if max_samples and len(samples) >= max_samples:
            break

    if not samples:
        raise LoaderError(
            f"no test cases found under {root}; check the extensions "
            f"{options.extensions} and label_from={options.label_from!r}"
        )

    payload: Dict[str, Any] = {
        "dataset": {
            "name": "sard",
            "root": str(root),
            "loader": "phase3.loaders.load_sard",
            "sample_count": len(samples),
            "vulnerable_count": sum(1 for s in samples if s["vulnerable"]),
            "benign_count": sum(1 for s in samples if not s["vulnerable"]),
            "label_from": options.label_from,
            "assume_vulnerable": options.assume_vulnerable,
            "unclassified": unclassified[:20],
            "unclassified_count": len(unclassified),
            "per_cwe": _per_cwe(samples),
            "digest": _digest(samples),
        },
        "samples": samples,
    }
    return payload


def _sard_label_from_directory(
    path: Path, options: SardOptions, root: Path
) -> Optional[bool]:
    """True/False for a vulnerable/benign test case, None if unrecognised.

    The immediate parent is checked first, on its own: a file directly in
    ``good/`` is benign even if a parent further up happens to be named
    ``vulnerable``.
    """
    parent = _has_marker([path.parent.name], options.safe_dirs)
    if parent:
        return False
    if _has_marker([path.parent.name], options.vulnerable_dirs):
        return True
    if options.assume_vulnerable and _has_marker(
        path.relative_to(root).parts[:-1], ("cwe",)
    ):
        # Only a file that sits in a CWE directory counts as an implied
        # vulnerable case, not a file that happens to be somewhere else.
        return True
    parts = path.relative_to(root).parts
    if _has_marker(parts, options.safe_dirs):
        return False
    if _has_marker(parts, options.vulnerable_dirs):
        return True
    return None


def _sard_label_from_metadata(
    path: Path, options: SardOptions
) -> Optional[bool]:
    """Read the label from the nearest ``metadata.csv`` above the test case.

    The table's column order is not fixed between releases, so the test-case
    name and the label are located by column header rather than by position.
    """
    name_columns = ("Name", "name", "File", "file", "File_Name", "ID", "Id")
    for directory in (path.parent, *path.parents):
        if directory == directory.parent:
            break
        for candidate in directory.glob("metadata.csv"):
            rows = candidate.read_text(encoding="utf-8", errors="replace").splitlines()
            if not rows:
                continue
            header = [column.strip().strip('"') for column in rows[0].split(",")]
            label_column = next(
                (c for c in options.safe_columns if c in header), None
            )
            if label_column is None:
                continue
            name_column = next(
                (c for c in name_columns if c in header),
                # Fall back to the first column, which is the name in the
                # single-column tables SARD also ships.
                header[0] if header else None,
            )
            if name_column is None:
                continue
            label_index = header.index(label_column)
            name_index = header.index(name_column)
            stem = path.stem
            for row in rows[1:]:
                fields = [f.strip().strip('"') for f in row.split(",")]
                if max(name_index, label_index) >= len(fields):
                    continue
                if stem in fields[name_index] or fields[name_index] == path.name:
                    value = fields[label_index].lower()
                    if value in options.vulnerable_values:
                        return True
                    if value:
                        return False
    return None


# -- real-world Hugging Face corpora: PrimeVul and Big-Vul --------------------
#
# The generic ``load_function_corpus`` above reads an old ``func``/``target``
# JSON convention, which is not what the Hugging Face mirrors actually serve:
# Big-Vul ships ``func_before``/``func_after``/``vul``/``CWE ID`` parquet and
# PrimeVul ships ``func``/``target``/``cwe`` (a list) JSONL. The loaders below
# read those real schemas. Two properties matter for this project:
#
# * **Good and bad stay separate.** A vulnerable function becomes a ``bad``
#   sample and its fix (or a benign function) becomes a ``good`` sample, so a
#   manifest always has an explicit benign population to measure FPR against.
#   A vulnerable-only manifest cannot produce a false-positive rate.
# * **Empty sources are refused.** A function that is missing or whitespace-only
#   is counted in ``skipped_empty`` and never written: an empty file is not a
#   benign sample, it is a missing sample, and scoring it as "safe" would
#   quietly inflate specificity.


@dataclass
class RealWorldOptions:
    """How to sample a real-world function corpus into a manifest."""

    # Keep only these weaknesses, e.g. ["CWE-122", "CWE-190"]. None keeps all.
    cwe_filter: Optional[Sequence[str]] = None
    # Cap on total samples after balancing. None keeps everything selected.
    limit: Optional[int] = None
    # Down-sample the majority class so vulnerable == benign. A benchmark that
    # is 97% benign measures a detector's patience, not its skill.
    balanced: bool = True
    seed: int = 42
    drop_duplicates: bool = True
    language: str = "c"
    suffix: str = ".c"
    # When set, ``file`` entries are stored relative to this directory (use the
    # directory that will contain the manifest) instead of as absolute paths,
    # so the manifest works on any checkout. ``dataset.root`` is then omitted
    # and the reader resolves against the manifest's own directory.
    relative_to: Optional[str | Path] = None
    # Big-Vul only: also emit each vulnerable row's ``func_after`` as a benign
    # twin. The fix is the closest possible "good" for that "bad".
    include_fix_as_benign: bool = True


def _normalise_cwe_filter(
    wanted: Optional[Sequence[str]],
) -> Optional[frozenset]:
    if not wanted:
        return None
    return frozenset(_canonical_cwe(re.sub(r"(?i)^cwe-?", "", str(w).strip())) for w in wanted)


def _iter_tabular(path: Path) -> List[Dict[str, Any]]:
    """Read parquet/CSV/JSONL/JSON into a list of row dicts.

    Parquet and CSV go through pandas (imported lazily so the core package
    does not require it); JSONL/JSON through the standard library.
    """
    suffix = path.suffix.lower()
    if suffix == ".parquet":
        try:
            import pandas as pd
        except ImportError as exc:
            raise LoaderError(
                "reading parquet needs pandas and pyarrow: pip install pandas pyarrow"
            ) from exc
        return [dict(r) for r in pd.read_parquet(path).to_dict(orient="records")]
    if suffix == ".csv":
        try:
            import pandas as pd
        except ImportError as exc:
            raise LoaderError("reading CSV needs pandas: pip install pandas") from exc
        return [dict(r) for r in pd.read_csv(path).to_dict(orient="records")]
    if suffix == ".jsonl":
        rows: List[Dict[str, Any]] = []
        for number, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise LoaderError(f"{path}:{number}: not valid JSON: {exc}") from exc
            if not isinstance(record, dict):
                raise LoaderError(f"{path}:{number}: expected an object")
            rows.append(record)
        return rows
    if suffix == ".json":
        payload = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(payload, dict):
            payload = payload.get("data") or payload.get("samples") or []
        if not isinstance(payload, list):
            raise LoaderError("expected a JSON array of function records")
        return [r for r in payload if isinstance(r, dict)]
    raise LoaderError(
        f"unsupported corpus file {path}: want .parquet, .csv, .jsonl or .json"
    )


def _sample_file_name(stem: str, variant: str, digest: str, suffix: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", stem)[:80].strip("_") or "func"
    return f"{safe}_{variant}_{digest}{suffix}"


def _store_sample_file(
    out_dir: Path,
    file_name: str,
    source: str,
    *,
    relative_to: Optional[Path],
) -> str:
    target = out_dir / file_name
    target.write_text(source, encoding="utf-8")
    if relative_to is not None:
        return str(target.resolve().relative_to(relative_to.resolve()))
    return str(target)


def _select_balanced(
    vuln: List[Dict[str, Any]],
    benign: List[Dict[str, Any]],
    options: Any,
) -> List[Dict[str, Any]]:
    """Merge the two classes, balancing and capping deterministically.

    Takes any options object with ``balanced``/``limit``/``seed`` (both
    ``RealWorldOptions`` and ``VulnLLMROptions`` qualify).
    """
    import random

    rng = random.Random(options.seed)
    rng.shuffle(vuln)
    rng.shuffle(benign)
    if options.balanced and vuln and benign:
        keep = min(len(vuln), len(benign))
        vuln, benign = vuln[:keep], benign[:keep]
    samples = vuln + benign
    if options.limit and len(samples) > options.limit:
        # Stratify the cap so a limit does not silently drop the minority class.
        import math

        per_class = max(1, math.ceil(options.limit / 2))
        samples = vuln[:per_class] + benign[:per_class]
        samples = samples[: options.limit]
    rng.shuffle(samples)
    return samples


def _materialize_selected(
    selected: List[Dict[str, Any]],
    out_dir: Path,
    *,
    relative_to: Optional[Path],
    suffix: str,
) -> List[Dict[str, Any]]:
    """Write source files for the selected candidates only.

    Balancing happens before any file hits disk, so candidates that lose the
    sample (duplicates aside) leave no orphan files behind.
    """
    for sample in selected:
        source = sample.pop("_source")
        stem = sample.pop("_stem")
        digest = _digest([{"sample_id": f"{stem}:{sample['variant']}:{source}"}])
        file_name = _sample_file_name(stem, sample["variant"], digest, suffix)
        sample["file"] = _store_sample_file(
            out_dir, file_name, source, relative_to=relative_to
        )
    return selected


def _realworld_payload(
    *,
    name: str,
    loader: str,
    source: str,
    samples: List[Dict[str, Any]],
    out_dir: Path,
    relative_to: Optional[Path],
    skipped_empty: int,
    skipped_no_cwe: int,
    limitations: str,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    dataset: Dict[str, Any] = {
        "name": name,
        "loader": loader,
        "source": source,
        "sample_count": len(samples),
        "vulnerable_count": sum(1 for s in samples if s["vulnerable"]),
        "benign_count": sum(1 for s in samples if not s["vulnerable"]),
        "granularity": "function",
        "skipped_empty": skipped_empty,
        "skipped_no_cwe": skipped_no_cwe,
        "limitations": limitations,
        "per_cwe": _per_cwe(samples),
        "digest": _digest(samples),
    }
    if relative_to is None:
        dataset["root"] = str(out_dir.resolve())
    if extra:
        dataset.update(extra)
    return {"dataset": dataset, "samples": samples}


def load_primevul(
    path: str | Path,
    options: Optional[RealWorldOptions] = None,
    *,
    out_dir: str | Path | None = None,
    max_samples: Optional[int] = None,
) -> Dict[str, Any]:
    """PrimeVul JSONL (Hugging Face ``starsofchance/PrimeVul`` layout).

    Each row carries ``func``, ``target`` (0/1), ``cwe`` (a list of NVD CWE
    ids), ``cve``, ``project`` and ``commit_id``. The paired test split is
    already balanced vulnerable/fixed; ``balanced=True`` (the default) keeps it
    that way after filtering.
    """
    options = options or RealWorldOptions()
    if max_samples is not None:
        options = replace(options, limit=max_samples)
    source_path = Path(path)
    if not source_path.is_file():
        raise LoaderError(f"corpus file does not exist: {source_path}")

    wanted = _normalise_cwe_filter(options.cwe_filter)
    rows = _iter_tabular(source_path)

    out = Path(out_dir) if out_dir else Path("datasets") / "primevul" / "functions"
    out.mkdir(parents=True, exist_ok=True)
    relative_to = Path(options.relative_to) if options.relative_to else None

    vuln: List[Dict[str, Any]] = []
    benign: List[Dict[str, Any]] = []
    seen: set[str] = set()
    skipped_empty = 0
    skipped_no_cwe = 0
    for index, record in enumerate(rows):
        source = record.get("func")
        if not isinstance(source, str) or not source.strip():
            skipped_empty += 1
            continue
        if options.drop_duplicates and source in seen:
            continue
        seen.add(source)

        cwes = _cwes_from_record(record, "cwe")
        target = record.get("target")
        vulnerable = str(target).strip().lower() in ("1", "true")
        if vulnerable and wanted and not (set(cwes) & wanted):
            skipped_no_cwe += 1
            continue
        if vulnerable and not cwes:
            skipped_no_cwe += 1
            continue

        project = str(record.get("project", "") or f"item{index}").replace("/", "_")
        cve = str(record.get("cve", "") or "")
        variant = "bad" if vulnerable else "good"
        sample = {
            # "_source" is the function text; popped when the file is written,
            # after balancing, so unselected candidates leave no files behind.
            "_source": source,
            "_stem": f"{project}_{record.get('idx', index)}",
            "sample_id": f"primevul_{record.get('idx', index)}_{variant}",
            "vulnerable": vulnerable,
            "cwe": cwes,
            "language": options.language,
            "function": None,
            "variant": variant,
            "group_id": str(record.get("commit_id", "") or project),
            "project": str(record.get("project", "") or project),
            "cve": cve,
            "description": (
                f"PrimeVul {'vulnerable' if vulnerable else 'fixed'} function "
                f"from {project}"
                + (f" ({cve}, {', '.join(cwes)})" if cve or cwes else "")
            ),
        }
        (vuln if vulnerable else benign).append(sample)

    if not vuln and not benign:
        raise LoaderError(f"no usable records in {source_path}")
    samples = _materialize_selected(
        _select_balanced(vuln, benign, options),
        out,
        relative_to=relative_to,
        suffix=options.suffix,
    )
    return _realworld_payload(
        name="primevul",
        loader="phase3.loaders.load_primevul",
        source=str(source_path),
        samples=samples,
        out_dir=out,
        relative_to=relative_to,
        skipped_empty=skipped_empty,
        skipped_no_cwe=skipped_no_cwe,
        limitations=(
            "Function-level real-world corpus. Each sample is one function "
            "written to its own file, not a buildable project. Vulnerable "
            "labels come from PrimeVul's NVD-check/one-function heuristics "
            "(human-level accuracy, ~86-92% on audit) and benign labels are "
            "post-fix or unchanged functions from the same commits, so some "
            "label noise remains: a precision or recall measured here is an "
            "approximation against that annotation, not a verified ground "
            "truth. Do not quote these numbers as a detection rate on real "
            "software without an audit of a sample."
        ),
        extra={"cwe_filter": sorted(wanted) if wanted else None},
    )


def load_bigvul_hf(
    path: str | Path,
    options: Optional[RealWorldOptions] = None,
    *,
    out_dir: str | Path | None = None,
    max_samples: Optional[int] = None,
) -> Dict[str, Any]:
    """Big-Vul in its real Hugging Face schema (``bstee615/bigvul`` layout).

    Rows carry ``func_before``, ``func_after``, ``vul`` (0/1), ``CWE ID``
    (``CWE-119`` or empty), ``CVE ID``, ``project`` and ``commit_id``. Each
    vulnerable row yields a ``bad`` sample (the code as it was) and, unless
    disabled, a ``good`` twin (the fix), which is the sharpest benign example
    for that weakness. Benign rows yield ``good`` samples of their code.
    """
    options = options or RealWorldOptions()
    if max_samples is not None:
        options = replace(options, limit=max_samples)
    source_path = Path(path)
    if not source_path.is_file():
        raise LoaderError(f"corpus file does not exist: {source_path}")

    wanted = _normalise_cwe_filter(options.cwe_filter)
    rows = _iter_tabular(source_path)

    out = Path(out_dir) if out_dir else Path("datasets") / "bigvul" / "functions"
    out.mkdir(parents=True, exist_ok=True)
    relative_to = Path(options.relative_to) if options.relative_to else None

    vuln: List[Dict[str, Any]] = []
    benign: List[Dict[str, Any]] = []
    seen: set[str] = set()
    skipped_empty = 0
    skipped_no_cwe = 0

    def stage(source: str, *, stem: str, variant: str, vulnerable: bool,
              cwes: List[str], record: Dict[str, Any], group: str) -> None:
        project = str(record.get("project", "") or stem)
        cve = str(record.get("CVE ID", "") or "")
        (vuln if vulnerable else benign).append(
            {
                "_source": source,
                "_stem": stem,
                "sample_id": f"bigvul_{stem}_{variant}",
                "vulnerable": vulnerable,
                "cwe": cwes,
                "language": options.language,
                "function": None,
                "variant": variant,
                "group_id": group,
                "project": project,
                "cve": cve,
                "description": (
                    f"Big-Vul {'vulnerable' if vulnerable else 'benign'} function "
                    f"from {project}"
                    + (f" ({cve}, {', '.join(cwes)})" if cve or cwes else "")
                ),
            }
        )

    for index, record in enumerate(rows):
        project = str(record.get("project", "") or f"item{index}").replace("/", "_")
        commit = str(record.get("commit_id", "") or f"row{index}")
        group = f"{project}_{commit}"
        stem = f"{project}_{index}"
        cwes = _cwes_from_record(record, "CWE ID")
        target = record.get("vul", record.get("target"))
        vulnerable = str(target).strip().lower() in ("1", "true")

        before = record.get("func_before", record.get("func"))
        after = record.get("func_after")
        if not isinstance(before, str) or not before.strip():
            skipped_empty += 1
            continue
        if options.drop_duplicates and before in seen:
            continue
        seen.add(before)
        if vulnerable:
            if wanted and not (set(cwes) & wanted):
                skipped_no_cwe += 1
                continue
            if not cwes:
                skipped_no_cwe += 1
                continue
            stage(before, stem=stem, variant="bad", vulnerable=True,
                  cwes=cwes, record=record, group=group)
            if options.include_fix_as_benign and isinstance(after, str) and after.strip():
                if after not in seen:
                    seen.add(after)
                    stage(after, stem=stem, variant="good", vulnerable=False,
                          cwes=cwes, record=record, group=group)
        else:
            stage(before, stem=stem, variant="good", vulnerable=False,
                  cwes=cwes, record=record, group=group)

    if not vuln and not benign:
        raise LoaderError(f"no usable records in {source_path}")
    samples = _materialize_selected(
        _select_balanced(vuln, benign, options),
        out,
        relative_to=relative_to,
        suffix=options.suffix,
    )
    return _realworld_payload(
        name="bigvul",
        loader="phase3.loaders.load_bigvul_hf",
        source=str(source_path),
        samples=samples,
        out_dir=out,
        relative_to=relative_to,
        skipped_empty=skipped_empty,
        skipped_no_cwe=skipped_no_cwe,
        limitations=(
            "Function-level real-world corpus. Each sample is one function "
            "written to its own file, not a buildable project. Big-Vul labels "
            "every function touched by a fix commit as vulnerable, which "
            "audits put at ~25% accuracy, so this manifest is noisier than "
            "PrimeVul: prefer PrimeVul for reported numbers and use Big-Vul "
            "for CWE coverage. A precision or recall measured here is an "
            "approximation against that annotation, not a verified ground "
            "truth. Do not quote these numbers as a detection rate on real "
            "software without an audit of a sample."
        ),
        extra={
            "cwe_filter": sorted(wanted) if wanted else None,
            "include_fix_as_benign": options.include_fix_as_benign,
        },
    )


# -- function-level corpora: Devign and Big-Vul (legacy JSON layout) -------


@dataclass
class FunctionCorpusOptions:
    """Options for a corpus of labelled functions rather than labelled files."""

    # CWE strings look like "CWE-119" or "119" in these corpora.
    cwe_key: str = "cwe"
    label_key: str = "target"
    source_key: str = "func"
    project_key: str = "project"
    # Big-Vul mixes multiple labels into one field.
    vulnerable_values: Sequence[str] = ("1", "true")
    # Both corpora label whole functions, so the source is written to its own
    # file for the analyzers. C sources need a C suffix to be routed correctly.
    language: str = "c"
    suffix: str = ".c"
    drop_duplicates: bool = True


def load_function_corpus(
    path: str | Path,
    name: str,
    options: Optional[FunctionCorpusOptions] = None,
    *,
    out_dir: str | Path | None = None,
    max_samples: Optional[int] = None,
) -> Dict[str, Any]:
    """Build a manifest for a Devign- or Big-Vul-style JSON array.

    The corpora store one labelled function per record rather than a path, so
    each function is written out as its own file; ``out_dir`` is where they go
    and defaults to ``datasets/<name>/functions``.

    The manifest records the label once, in ``vulnerable``. A second field
    spelling it out in prose (``"labelled vulnerable"``) or in the Juliet
    ``variant: bad`` spelling would be a second channel for the same
    information, and a manifest is more likely than the source to reach a
    prompt by accident.
    """
    options = options or FunctionCorpusOptions()
    source_path = Path(path)
    if not source_path.is_file():
        raise LoaderError(f"corpus file does not exist: {source_path}")

    payload = json.loads(source_path.read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        payload = payload.get("data") or payload.get("samples") or []
    if not isinstance(payload, list):
        raise LoaderError("expected a JSON array of function records")

    out_dir = Path(out_dir) if out_dir else Path("datasets") / name / "functions"
    out_dir.mkdir(parents=True, exist_ok=True)

    samples: List[Dict[str, Any]] = []
    seen: set[str] = set()
    skipped_no_source = 0
    for index, record in enumerate(payload):
        if not isinstance(record, dict):
            continue
        source = record.get(options.source_key)
        if not isinstance(source, str) or not source.strip():
            skipped_no_source += 1
            continue
        project = str(record.get(options.project_key, "") or f"item{index}")
        digest = _digest([{"sample_id": f"{project}:{source}"}])
        if options.drop_duplicates:
            if source in seen:
                continue
            seen.add(source)

        target = record.get(options.label_key)
        vulnerable = str(target).strip().lower() in options.vulnerable_values
        cwes = _cwes_from_record(record, options.cwe_key)

        file_name = f"{project.replace('/', '_')}_{digest}{options.suffix}"
        target_path = out_dir / file_name
        target_path.write_text(source, encoding="utf-8")

        samples.append(
            {
                "sample_id": f"{project}_{index}_{digest}",
                "file": str(target_path),
                "vulnerable": vulnerable,
                "cwe": cwes,
                "language": options.language,
                "function": None,
                "project": project,
            }
        )
        if max_samples and len(samples) >= max_samples:
            break

    if not samples:
        raise LoaderError(
            f"no usable records in {source_path}; expected a "
            f"{options.source_key!r} field on each record"
        )

    return {
        "dataset": {
            "name": name,
            "root": str(out_dir.resolve()),
            "loader": "phase3.loaders.load_function_corpus",
            "source": str(source_path),
            "sample_count": len(samples),
            "vulnerable_count": sum(1 for s in samples if s["vulnerable"]),
            "benign_count": sum(1 for s in samples if not s["vulnerable"]),
            "skipped_without_source": skipped_no_source,
            "granularity": "function",
            "limitations": (
                "Function-level corpus: each sample is one extracted function "
                "written to its own file, not a whole project build. Labels come "
                "from the corpus's own historical annotation and are known to "
                "contain noise, so a precision or recall measured here is an "
                "approximation against that annotation, not a verified ground "
                "truth. Do not quote these numbers as a detection rate on real "
                "software without an audit of a sample."
            ),
            "per_cwe": _per_cwe(samples),
            "digest": _digest(samples),
        },
        "samples": samples,
    }


def _with(options: Optional[FunctionCorpusOptions], **overrides: Any):
    """Caller-supplied options layered over the corpus defaults."""
    base = options or FunctionCorpusOptions()
    return replace(base, **overrides)


def load_devign(path: str | Path, **kwargs: Any) -> Dict[str, Any]:
    """Devign: function-level C, labelled 0/1, no CWE annotation."""
    options = _with(kwargs.pop("options", None), cwe_key="", language="c", suffix=".c")
    return load_function_corpus(path, "devign", options, **kwargs)


def load_big_vul(path: str | Path, **kwargs: Any) -> Dict[str, Any]:
    """Big-Vul: function-level C, labelled 0/1, with a CWE column."""
    options = _with(
        kwargs.pop("options", None), cwe_key="cwe", language="c", suffix=".c"
    )
    return load_function_corpus(path, "big_vul", options, **kwargs)


def _cwes_from_record(record: Dict[str, Any], key: str) -> List[str]:
    """Normalise a corpus CWE field into ids, or nothing when absent."""
    if not key:
        return []
    raw = record.get(key)
    if raw is None:
        return []
    values: Iterable[Any]
    if isinstance(raw, (list, tuple, set)):
        values = raw
    else:
        # Big-Vul packs several classes into one string, e.g. "119, 120, 787".
        values = re.split(r"[,/|;\s]+", str(raw))
    out: List[str] = []
    for value in values:
        found = CWE_DIR_RE.findall(str(value)) or (
            [str(value).strip()]
            if str(value).strip().isdigit()
            else []
        )
        for digits in found:
            cwe = _canonical_cwe(digits)
            if cwe not in out:
                out.append(cwe)
    return out


def _per_cwe(samples: Sequence[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for sample in samples:
        for cwe in sample.get("cwe", []) or []:
            counts[cwe] = counts.get(cwe, 0) + 1
    return dict(sorted(counts.items()))


def write_manifest(payload: Dict[str, Any], path: str | Path) -> Path:
    """Write a manifest and return its path."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return path


# -- VulnLLM-R test data (UCSB-SURFI/VulnLLM-R-Test-Data) ---------------------
#
# The paper's function-level test set: one row per function with ``code``,
# ``CWE_ID`` (exactly one CWE per row), ``target`` (0/1), ``language``
# (c/python/java), ``RELATED_CWE`` and ``function_name``. Unlike the PrimeVul
# and Big-Vul mirrors, these samples passed the authors' LLM-assisted human
# validation, so the labels are the cleanest available short of a manual audit.
#
# Files are laid out grouped by CWE, like the paper's own
# ``datasets/test/`` tree::
#
#     <out_dir>/<split>/<language>/CWE-787/bad/<stem>_bad_<hash>.c
#     <out_dir>/<split>/<language>/CWE-787/good/<stem>_good_<hash>.c
#
# so a per-CWE result is a directory listing away. Java rows are materialized
# on disk but this project's analyzers (Bandit/Cppcheck/Flawfinder) do
# not cover Java, so include only ``c`` and ``python`` in a scored manifest.


SUFFIX_BY_LANGUAGE = {"c": ".c", "cpp": ".cpp", "python": ".py", "java": ".java"}


@dataclass
class VulnLLMROptions:
    """How to sample the VulnLLM-R test set into a manifest."""

    # Score only these languages. Java is written to disk but left out of a
    # scored manifest: no analyzer in this project reads it, and scoring it
    # would count every sample as a miss for reasons unrelated to detection.
    languages: Sequence[str] = ("c", "python")
    split: str = "function_level"
    cwe_filter: Optional[Sequence[str]] = None
    limit: Optional[int] = None
    balanced: bool = False
    seed: int = 42
    drop_duplicates: bool = True
    relative_to: Optional[str | Path] = None


def load_vulnllm_r(
    path: str | Path,
    options: Optional[VulnLLMROptions] = None,
    *,
    out_dir: str | Path | None = None,
    max_samples: Optional[int] = None,
) -> Dict[str, Any]:
    """VulnLLM-R function/repo-level parquet (``UCSB-SURFI`` layout)."""
    options = options or VulnLLMROptions()
    if max_samples is not None:
        options = replace(options, limit=max_samples)
    source_path = Path(path)
    if not source_path.is_file():
        raise LoaderError(f"corpus file does not exist: {source_path}")

    wanted = _normalise_cwe_filter(options.cwe_filter)
    keep_languages = {str(l).lower() for l in (options.languages or [])}
    rows = _iter_tabular(source_path)

    out = Path(out_dir) if out_dir else Path("datasets") / "vulnllm_r"
    out.mkdir(parents=True, exist_ok=True)
    relative_to = Path(options.relative_to) if options.relative_to else None

    vuln: List[Dict[str, Any]] = []
    benign: List[Dict[str, Any]] = []
    seen: set[str] = set()
    skipped_empty = 0
    skipped_no_cwe = 0
    skipped_language = 0
    for index, record in enumerate(rows):
        language = str(record.get("language", "") or "").lower()
        if keep_languages and language not in keep_languages:
            skipped_language += 1
            continue
        source = record.get("code")
        if not isinstance(source, str) or not source.strip():
            skipped_empty += 1
            continue
        if options.drop_duplicates and source in seen:
            continue
        seen.add(source)

        raw_cwe = record.get("CWE_ID")
        try:
            cwe_values = [str(x) for x in list(raw_cwe)]
        except TypeError:
            cwe_values = [str(raw_cwe)] if raw_cwe else []
        cwes = _cwes_from_record({"cwe": cwe_values}, "cwe")
        target = record.get("target")
        vulnerable = str(target).strip().lower() in ("1", "true")
        if wanted and not (set(cwes) & wanted):
            skipped_no_cwe += 1
            continue
        if vulnerable and not cwes:
            skipped_no_cwe += 1
            continue

        variant = "bad" if vulnerable else "good"
        cwe_dir = cwes[0] if cwes else "CWE-unknown"
        func_name = str(record.get("function_name", "") or f"func{index}")
        stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", func_name)[:60].strip("_") or "func"
        group = f"{options.split}/{language}/{cwe_dir}/{variant}"
        sample = {
            "_source": source,
            "_stem": stem,
            "_groupdir": group,
            "sample_id": f"vulnllmr_{options.split}_{record.get('idx', index)}_{variant}",
            "vulnerable": vulnerable,
            "cwe": cwes,
            "language": language,
            "function": func_name or None,
            "variant": variant,
            "group_id": cwe_dir,
            "related_cwe": sorted(
                {_canonical_cwe(d) for v in _as_list(record.get("RELATED_CWE"))
                 for d in CWE_DIR_RE.findall(str(v))}
            ),
            "description": (
                f"VulnLLM-R {options.split} {language} "
                f"{'vulnerable' if vulnerable else 'benign'} function "
                f"{func_name} ({', '.join(cwes)})"
            ),
        }
        (vuln if vulnerable else benign).append(sample)

    if not vuln and not benign:
        raise LoaderError(f"no usable records in {source_path}")
    selected = _select_balanced(vuln, benign, options)
    for sample in selected:
        source = sample.pop("_source")
        stem = sample.pop("_stem")
        groupdir = Path(sample.pop("_groupdir"))
        digest = _digest([{"sample_id": f"{stem}:{sample['variant']}:{source}"}])
        suffix = SUFFIX_BY_LANGUAGE.get(sample["language"], ".txt")
        file_name = _sample_file_name(stem, sample["variant"], digest, suffix)
        target_dir = out / groupdir
        target_dir.mkdir(parents=True, exist_ok=True)
        sample["file"] = _store_sample_file(
            target_dir, file_name, source, relative_to=relative_to
        )
    return _realworld_payload(
        name=f"vulnllm_r_{options.split}",
        loader="phase3.loaders.load_vulnllm_r",
        source=str(source_path),
        samples=selected,
        out_dir=out,
        relative_to=relative_to,
        skipped_empty=skipped_empty,
        skipped_no_cwe=skipped_no_cwe,
        limitations=(
            "VulnLLM-R function-level test set: real project functions plus "
            "Juliet/SVEN/SecCodePLT cases that passed the authors' "
            "LLM-assisted human validation, de-duplicated by 20-token n-gram "
            "against their training set. Cleaner labels than Big-Vul, but a "
            "benchmark annotation all the same: treat a precision or recall "
            "measured here as an approximation, not a verified ground truth. "
            "Their reported metric is CWE-strict F1 (exact CWE must match); "
            "this project's matcher can require the same via "
            "SCENARIO_PHASE3_REQUIRE_CWE=true."
        ),
        extra={
            "split": options.split,
            "languages": sorted(keep_languages),
            "skipped_language": skipped_language,
            "cwe_filter": sorted(wanted) if wanted else None,
        },
    )


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    try:
        return list(value)
    except TypeError:
        return [value]
