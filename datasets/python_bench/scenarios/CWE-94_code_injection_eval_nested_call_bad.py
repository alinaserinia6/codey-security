"""eval_nested_call (CWE-94) - bad variant.

Generated benchmark file. The bad variant is the vulnerable form of this scenario.
"""
import os


def apply_transform(payload):
    return eval("os.path.join(" + payload + ")")
