"""open_join_request (CWE-22) - bad variant.

Generated benchmark file. The bad variant is the vulnerable form of this scenario.
"""
import os

from flask import request


def read_upload(name):
    return open(os.path.join("/srv/uploads", name)).read()
