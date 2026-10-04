"""eval_request_field (CWE-94) - good variant.

Generated benchmark file. The good variant is the repaired form of this scenario.
"""
import ast


def compute(expression):
    return ast.literal_eval(expression)
