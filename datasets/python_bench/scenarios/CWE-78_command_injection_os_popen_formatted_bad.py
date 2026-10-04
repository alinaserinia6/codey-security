"""os_popen_formatted (CWE-78) - bad variant.

Generated benchmark file. The bad variant is the vulnerable form of this scenario.
"""
import os


def fetch_page(host):
    os.popen("curl http://" + host)


def handler(host):
    fetch_page(host)
