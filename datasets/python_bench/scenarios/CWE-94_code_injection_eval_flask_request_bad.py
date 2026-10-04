"""eval_flask_request (CWE-94) - bad variant.

Generated benchmark file. The bad variant is the vulnerable form of this scenario.
"""
from flask import request


def calculate():
    return eval(request.args.get("expression", "0"))
