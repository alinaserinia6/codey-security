"""exec_request_field (CWE-94) - good variant.

Generated benchmark file. The good variant is the repaired form of this scenario.
"""
import subprocess


def run_console_command(statement):
    subprocess.run(["sh", "-c", statement], check=False)
