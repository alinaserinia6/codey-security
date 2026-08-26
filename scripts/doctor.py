#!/usr/bin/env python3
from __future__ import annotations
import shutil
import sys

commands = ["python", "cppcheck", "flawfinder", "clang", "scan-build"]
for command in commands:
    path = shutil.which(command)
    print(f"{command:12} {'OK: ' + path if path else 'MISSING'}")

try:
    import tree_sitter
    print(f"{'tree-sitter':12} OK: {getattr(tree_sitter, '__version__', 'installed')}")
except Exception as exc:
    print(f"{'tree-sitter':12} MISSING: {exc}")

for module in ("tree_sitter_python", "tree_sitter_c", "tree_sitter_cpp", "bandit"):
    try:
        __import__(module)
        status = "OK"
    except Exception as exc:
        status = f"MISSING: {exc}"
    print(f"{module:12} {status}")
