"""subprocess_popen_shell (CWE-78) - bad variant.

Generated benchmark file. The bad variant is the vulnerable form of this scenario.
"""
import subprocess


def backup_database(name):
    subprocess.Popen("pg_dump " + name, shell=True)
