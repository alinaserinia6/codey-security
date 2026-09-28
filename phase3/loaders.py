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


# -- function-level corpora: Devign and Big-Vul ---------------------------


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
