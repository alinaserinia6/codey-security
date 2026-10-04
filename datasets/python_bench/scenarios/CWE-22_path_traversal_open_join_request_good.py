"""open_join_request (CWE-22) - good variant.

Generated benchmark file. The good variant is the repaired form of this scenario.
"""
import os

from flask import request


def read_upload(name):
    safe = os.path.basename(name)
    return open(os.path.join("/srv/uploads", safe)).read()
