"""render_template_string_request (CWE-1336) - bad variant.

Generated benchmark file. The bad variant is the vulnerable form of this scenario.
"""
from flask import render_template_string, request


def preview():
    return render_template_string(request.args.get("template", ""))
