"""eval_flask_request (CWE-94) - good variant.

Generated benchmark file. The good variant is the repaired form of this scenario.
"""
import ast

from flask import request


def calculate():
    return ast.literal_eval(request.args.get("expression", "0"))
