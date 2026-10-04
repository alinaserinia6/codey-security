"""subprocess_popen_shell (CWE-78) - good variant.

Generated benchmark file. The good variant is the repaired form of this scenario.
"""
import subprocess


def backup_database(name):
    subprocess.Popen(["pg_dump", name], shell=False)
