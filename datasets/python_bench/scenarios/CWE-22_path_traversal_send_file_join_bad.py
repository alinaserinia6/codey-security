"""send_file_join (CWE-22) - bad variant.

Generated benchmark file. The bad variant is the vulnerable form of this scenario.
"""
import os

from flask import send_file


def download(name):
    return send_file(os.path.join("/srv/files", name))
