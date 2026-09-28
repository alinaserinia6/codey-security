"""Generate a labelled Python benchmark for the vulnerability classes in scope.

The proposal evaluates on Juliet for C, SARD, Devign and Big-Vul, but none of
those cover the Python families the proposal also claims (unsafe
deserialization, template injection, dangerous API use). Bandit is the Python
baseline to compare against, and it needs a labelled Python corpus to be
measured on, so this script generates one.

The corpus is paired Juliet-style: every scenario exists twice, as ``_bad`` and
as ``_good``, with the same shape and the same entry point, differing only in
whether the value reaching the sink is attacker-controlled. That pairing is
what makes the benchmark useful for measuring false alarms, which is the
quantity the whole design is trying to reduce -- a corpus of unrelated
vulnerable files can only measure recall.

The generated files are synthetic and their scenario names are embedded in the
filename and the identifiers, so they are useful for controlled comparison and
not a substitute for SARD. ``phase2.sanitize`` strips those names before the
file reaches an agent, which keeps the measurement honest.

The output is deterministic: the same script version always produces byte
identical files, so results are reproducible.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

GENERATOR_VERSION = "1"


@dataclass(frozen=True)
class Scenario:
    """One vulnerability pattern, in both a vulnerable and a repaired form."""

    cwe: str
    family: str
    name: str
    bad: str
    good: str
    sink_line_hint: int = 0


def _header(scenario: str, cwe: str, variant: str) -> str:
    """A Juliet-style banner.

    The label is deliberately present in the source, exactly as it is in Juliet.
    ``phase2.sanitize`` removes it before any agent sees the file, so the label
    is recoverable by the harness and invisible to the model.
    """
    return (
        f'"""{scenario} ({cwe}) - {variant} variant.\n\n'
        f"Generated benchmark file. The {variant} variant is the "
        f"{'vulnerable' if variant == 'bad' else 'repaired'} form of this scenario.\n"
        '"""\n'
    )


# ---------------------------------------------------------------------------
# Command injection (CWE-78)
# ---------------------------------------------------------------------------
_COMMAND_INJECTION = [
    Scenario(
        cwe="CWE-78",
        family="command_injection",
        name="subprocess_shell_true",
        bad='''
import subprocess
import sys


def run_user_command(command):
    subprocess.call(command, shell=True)


if __name__ == "__main__":
    run_user_command(sys.argv[1])
''',
        good='''
import subprocess
import sys


def run_user_command(command):
    subprocess.call(command.split(), shell=False)


if __name__ == "__main__":
    run_user_command(sys.argv[1])
''',
    ),
    Scenario(
        cwe="CWE-78",
        family="command_injection",
        name="os_system_argv",
        bad='''
import os
import sys


def list_directory(path):
    os.system("ls " + path)


if __name__ == "__main__":
    list_directory(sys.argv[1])
''',
        good='''
import os
import sys


def list_directory(path):
    os.system("ls " + os.path.basename(path))


if __name__ == "__main__":
    list_directory(sys.argv[1])
''',
    ),
    Scenario(
        cwe="CWE-78",
        family="command_injection",
        name="os_popen_formatted",
        bad='''
import os


def fetch_page(host):
    os.popen("curl http://" + host)


def handler(host):
    fetch_page(host)
''',
        good='''
import subprocess


def fetch_page(host):
    subprocess.run(["curl", host], check=False)


def handler(host):
    fetch_page(host)
''',
    ),
    Scenario(
        cwe="CWE-78",
        family="command_injection",
        name="subprocess_popen_shell",
        bad='''
import subprocess


def backup_database(name):
    subprocess.Popen("pg_dump " + name, shell=True)
''',
        good='''
import subprocess


def backup_database(name):
    subprocess.Popen(["pg_dump", name], shell=False)
''',
    ),
]

# ---------------------------------------------------------------------------
# Code injection (CWE-94)
# ---------------------------------------------------------------------------
_CODE_INJECTION = [
    Scenario(
        cwe="CWE-94",
        family="code_injection",
        name="eval_request_field",
        bad='''
def compute(expression):
    return eval(expression)
''',
        good='''
import ast


def compute(expression):
    return ast.literal_eval(expression)
''',
    ),
    Scenario(
        cwe="CWE-94",
        family="code_injection",
        name="exec_request_field",
        bad='''
def run_console_command(statement):
    exec(statement)
''',
        good='''
import subprocess


def run_console_command(statement):
    subprocess.run(["sh", "-c", statement], check=False)
''',
    ),
    Scenario(
        cwe="CWE-94",
        family="code_injection",
        name="eval_flask_request",
        bad='''
from flask import request


def calculate():
    return eval(request.args.get("expression", "0"))
''',
        good='''
import ast

from flask import request


def calculate():
    return ast.literal_eval(request.args.get("expression", "0"))
''',
    ),
    Scenario(
        cwe="CWE-94",
        family="code_injection",
        name="eval_nested_call",
        bad='''
import os


def apply_transform(payload):
    return eval("os.path.join(" + payload + ")")
''',
        good='''
import json
import os


def apply_transform(payload):
    return os.path.join(*json.loads(payload))
''',
    ),
]

# ---------------------------------------------------------------------------
# Server-side template injection (CWE-1336)
# ---------------------------------------------------------------------------
_TEMPLATE_INJECTION = [
    Scenario(
        cwe="CWE-1336",
        family="template_injection",
        name="render_template_string_argv",
        bad='''
from flask import render_template_string


def render_greeting(name):
    return render_template_string("Hello " + name)
''',
        good='''
from flask import render_template


def render_greeting(name):
    return render_template("greeting.html", name=name)
''',
    ),
    Scenario(
        cwe="CWE-1336",
        family="template_injection",
        name="jinja_from_string",
        bad='''
from jinja2 import Template


def render_profile(profile):
    return Template(profile).render()
''',
        good='''
from jinja2 import Environment, FileSystemLoader


def render_profile(profile):
    env = Environment(loader=FileSystemLoader("templates"))
    return env.get_template("profile.html").render(name=profile)
''',
    ),
    Scenario(
        cwe="CWE-1336",
        family="template_injection",
        name="render_template_string_request",
        bad='''
from flask import render_template_string, request


def preview():
    return render_template_string(request.args.get("template", ""))
''',
        good='''
from flask import render_template, request


def preview():
    return render_template("preview.html", body=request.args.get("body", ""))
''',
    ),
    Scenario(
        cwe="CWE-1336",
        family="template_injection",
        name="template_concat",
        bad='''
from jinja2 import Template


def render_email(subject, body):
    return Template("<p>" + subject + "</p><p>" + body + "</p>").render()
''',
        good='''
from flask import render_template


def render_email(subject, body):
    return render_template("email.html", subject=subject, body=body)
''',
    ),
]

# ---------------------------------------------------------------------------
# Unsafe deserialization (CWE-502)
# ---------------------------------------------------------------------------
_UNSAFE_DESERIALIZATION = [
    Scenario(
        cwe="CWE-502",
        family="unsafe_deserialization",
        name="pickle_loads_request",
        bad='''
import pickle

from flask import request


def load_state():
    return pickle.loads(request.get_data())
''',
        good='''
import json

from flask import request


def load_state():
    return json.loads(request.get_data())
''',
    ),
    Scenario(
        cwe="CWE-502",
        family="unsafe_deserialization",
        name="yaml_load_unsafe",
        bad='''
import yaml


def parse_config(raw):
    return yaml.load(raw)
''',
        good='''
import yaml


def parse_config(raw):
    return yaml.safe_load(raw)
''',
    ),
    Scenario(
        cwe="CWE-502",
        family="unsafe_deserialization",
        name="marshal_loads_file",
        bad='''
import marshal


def read_cache(path):
    with open(path, "rb") as handle:
        return marshal.loads(handle.read())
''',
        good='''
import json


def read_cache(path):
    with open(path, "rb") as handle:
        return json.loads(handle.read())
''',
    ),
    Scenario(
        cwe="CWE-502",
        family="unsafe_deserialization",
        name="pickle_loads_bytes",
        bad='''
import pickle


def restore_session(blob):
    return pickle.loads(blob)
''',
        good='''
import json


def restore_session(blob):
    return json.loads(blob)
''',
    ),
]

# ---------------------------------------------------------------------------
# SQL injection (CWE-89)
# ---------------------------------------------------------------------------
_SQL_INJECTION = [
    Scenario(
        cwe="CWE-89",
        family="sql_injection",
        name="cursor_execute_fstring",
        bad='''
import sqlite3


def find_user(connection, name):
    cursor = connection.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return cursor.fetchall()
''',
        good='''
import sqlite3


def find_user(connection, name):
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
    return cursor.fetchall()
''',
    ),
    Scenario(
        cwe="CWE-89",
        family="sql_injection",
        name="cursor_execute_concat",
        bad='''
import sqlite3


def count_orders(connection, user):
    cursor = connection.cursor()
    cursor.execute("SELECT COUNT(*) FROM orders WHERE user = " + user)
    return cursor.fetchone()
''',
        good='''
import sqlite3


def count_orders(connection, user):
    cursor = connection.cursor()
    cursor.execute("SELECT COUNT(*) FROM orders WHERE user = ?", (user,))
    return cursor.fetchone()
''',
    ),
    Scenario(
        cwe="CWE-89",
        family="sql_injection",
        name="raw_query_format",
        bad='''
from sqlalchemy import text


def recent_posts(session, limit):
    return session.execute(text(f"SELECT * FROM posts LIMIT {limit}"))
''',
        good='''
from sqlalchemy import text


def recent_posts(session, limit):
    return session.execute(
        text("SELECT * FROM posts LIMIT :limit"), {"limit": limit}
    )
''',
    ),
    Scenario(
        cwe="CWE-89",
        family="sql_injection",
        name="execute_percent_format",
        bad='''
import sqlite3


def delete_session(connection, token):
    cursor = connection.cursor()
    cursor.execute("DELETE FROM sessions WHERE token = '%s'" % token)
    return cursor.rowcount
''',
        good='''
import sqlite3


def delete_session(connection, token):
    cursor = connection.cursor()
    cursor.execute("DELETE FROM sessions WHERE token = ?", (token,))
    return cursor.rowcount
''',
    ),
]

# ---------------------------------------------------------------------------
# Path traversal (CWE-22)
# ---------------------------------------------------------------------------
_PATH_TRAVERSAL = [
    Scenario(
        cwe="CWE-22",
        family="path_traversal",
        name="open_join_request",
        bad='''
import os

from flask import request


def read_upload(name):
    return open(os.path.join("/srv/uploads", name)).read()
''',
        good='''
import os

from flask import request


def read_upload(name):
    safe = os.path.basename(name)
    return open(os.path.join("/srv/uploads", safe)).read()
''',
    ),
    Scenario(
        cwe="CWE-22",
        family="path_traversal",
        name="send_file_join",
        bad='''
import os

from flask import send_file


def download(name):
    return send_file(os.path.join("/srv/files", name))
''',
        good='''
import os

from flask import send_file


def download(name):
    safe = os.path.realpath(os.path.join("/srv/files", os.path.basename(name)))
    return send_file(safe)
''',
    ),
    Scenario(
        cwe="CWE-22",
        family="path_traversal",
        name="os_remove_join",
        bad='''
import os


def purge_report(report_id):
    os.remove("/var/reports/" + report_id)
''',
        good='''
import os


def purge_report(report_id):
    safe = os.path.basename(report_id)
    os.remove(os.path.join("/var/reports", safe))
''',
    ),
    Scenario(
        cwe="CWE-22",
        family="path_traversal",
        name="shutil_rmtree_user",
        bad='''
import shutil


def clean_workspace(folder):
    shutil.rmtree(folder)
''',
        good='''
import os
import shutil


def clean_workspace(folder):
    root = os.path.abspath("/var/workspaces")
    target = os.path.abspath(os.path.join(root, os.path.basename(folder)))
    if os.path.commonpath([root, target]) == root:
        shutil.rmtree(target)
''',
    ),
]

ALL_SCENARIOS: List[Scenario] = [
    *_COMMAND_INJECTION,
    *_CODE_INJECTION,
    *_TEMPLATE_INJECTION,
    *_UNSAFE_DESERIALIZATION,
    *_SQL_INJECTION,
    *_PATH_TRAVERSAL,
]


def _sanitized_code(scenario: Scenario, variant: str) -> str:
    body = scenario.bad if variant == "bad" else scenario.good
    return _header(scenario.name, scenario.cwe, variant) + body.lstrip("\n")


def _sink_line(code: str) -> Optional[int]:
    """First line mentioning a sink, used as the reference location.

    The manifest carries this so a tool that only reports a line can still be
    scored, and so a human reviewing a result has somewhere to start.
    """
    sinks = (
        "subprocess.call", "subprocess.run", "subprocess.Popen", "os.system",
        "os.popen", "eval(", "exec(", "render_template_string", "Template(",
        "pickle.loads", "yaml.load(", "marshal.loads", "cursor.execute",
        "session.execute", "open(", "send_file(", "os.remove(", "shutil.rmtree",
    )
    for number, line in enumerate(code.splitlines(), start=1):
        stripped = line.strip()
        for sink in sinks:
            if sink in stripped and not stripped.startswith("#"):
                return number
    return None


def build(
    output_dir: Path,
    *,
    scenarios: Optional[Sequence[Scenario]] = None,
) -> Dict[str, object]:
    """Write every scenario as a ``_bad``/``_good`` pair and return the manifest."""
    scenarios = list(scenarios if scenarios is not None else ALL_SCENARIOS)
    samples: List[Dict[str, object]] = []
    family_root = output_dir / "scenarios"
    family_root.mkdir(parents=True, exist_ok=True)

    for scenario in scenarios:
        for variant in ("bad", "good"):
            stem = f"{scenario.cwe}_{scenario.family}_{scenario.name}_{variant}"
            path = family_root / f"{stem}.py"
            code = _sanitized_code(scenario, variant)
            path.write_text(code, encoding="utf-8")
            samples.append(
                {
                    "sample_id": stem,
                    "file": str(path.resolve()),
                    "vulnerable": variant == "bad",
                    "cwe": [scenario.cwe],
                    "line": _sink_line(code),
                    "function": None,
                    "group_id": f"{scenario.cwe}_{scenario.family}_{scenario.name}",
                    "variant": variant,
                    "scenario": f"{scenario.cwe}_{scenario.family}_{scenario.name}",
                    "language": "python",
                    "description": (
                        f"{variant} variant of the {scenario.family} scenario "
                        f"{scenario.name} ({scenario.cwe})"
                    ),
                }
            )

    per_cwe: Dict[str, int] = {}
    for sample in samples:
        per_cwe[str(sample["cwe"][0])] = per_cwe.get(str(sample["cwe"][0]), 0) + 1

    manifest = {
        "dataset": {
            "name": "synthetic-python-paired",
            "root": str(output_dir.resolve()),
            "generator": "scripts/make_python_bench.py",
            "generator_version": GENERATOR_VERSION,
            "synthetic": True,
            "sample_count": len(samples),
            "vulnerable_count": sum(1 for s in samples if s["vulnerable"]),
            "benign_count": sum(1 for s in samples if not s["vulnerable"]),
            "pairing": "each scenario exists as a _bad and a _good variant",
            "limitations": (
                "Synthetic paired corpus generated from templates. It covers the "
                "Python families in the proposal scope and is intended for "
                "controlled comparison of detection and false-alarm rates, "
                "not as a substitute for SARD or any real-world Python corpus."
            ),
            "per_cwe": dict(sorted(per_cwe.items())),
            "digest": hashlib.sha256(
                "".join(s["sample_id"] for s in samples).encode("utf-8")
            ).hexdigest()[:16],
        },
        "samples": samples,
    }

    manifest_path = output_dir / "python_bench.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return manifest


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "datasets" / "python_bench",
        help="directory to write scenarios and the manifest into",
    )
    parser.add_argument("--list", action="store_true", help="list scenarios and exit")
    args = parser.parse_args(argv)

    if args.list:
        for scenario in ALL_SCENARIOS:
            print(f"{scenario.cwe:10s} {scenario.family:24s} {scenario.name}")
        print(f"\n{len(ALL_SCENARIOS)} scenarios, {len(ALL_SCENARIOS) * 2} files")
        return 0

    manifest = build(args.out)
    info = manifest["dataset"]
    print(f"wrote {info['sample_count']} files to {args.out}")
    print(f"  vulnerable: {info['vulnerable_count']}")
    print(f"  benign:     {info['benign_count']}")
    print(f"  per CWE:    {info['per_cwe']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
