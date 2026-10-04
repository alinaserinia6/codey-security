"""pickle_loads_request (CWE-502) - good variant.

Generated benchmark file. The good variant is the repaired form of this scenario.
"""
import json

from flask import request


def load_state():
    return json.loads(request.get_data())
