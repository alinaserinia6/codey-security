"""render_template_string_request (CWE-1336) - good variant.

Generated benchmark file. The good variant is the repaired form of this scenario.
"""
from flask import render_template, request


def preview():
    return render_template("preview.html", body=request.args.get("body", ""))
