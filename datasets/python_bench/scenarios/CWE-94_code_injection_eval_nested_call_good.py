"""eval_nested_call (CWE-94) - good variant.

Generated benchmark file. The good variant is the repaired form of this scenario.
"""
import json
import os


def apply_transform(payload):
    return os.path.join(*json.loads(payload))
