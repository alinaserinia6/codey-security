"""marshal_loads_file (CWE-502) - good variant.

Generated benchmark file. The good variant is the repaired form of this scenario.
"""
import json


def read_cache(path):
    with open(path, "rb") as handle:
        return json.loads(handle.read())
