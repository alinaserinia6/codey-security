"""pickle_loads_bytes (CWE-502) - good variant.

Generated benchmark file. The good variant is the repaired form of this scenario.
"""
import json


def restore_session(blob):
    return json.loads(blob)
