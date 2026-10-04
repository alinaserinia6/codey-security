"""os_popen_formatted (CWE-78) - good variant.

Generated benchmark file. The good variant is the repaired form of this scenario.
"""
import subprocess


def fetch_page(host):
    subprocess.run(["curl", host], check=False)


def handler(host):
    fetch_page(host)
