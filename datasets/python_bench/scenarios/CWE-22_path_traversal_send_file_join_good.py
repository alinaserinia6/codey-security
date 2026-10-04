"""send_file_join (CWE-22) - good variant.

Generated benchmark file. The good variant is the repaired form of this scenario.
"""
import os

from flask import send_file


def download(name):
    safe = os.path.realpath(os.path.join("/srv/files", os.path.basename(name)))
    return send_file(safe)
