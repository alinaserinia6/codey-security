"""template_concat (CWE-1336) - good variant.

Generated benchmark file. The good variant is the repaired form of this scenario.
"""
from flask import render_template


def render_email(subject, body):
    return render_template("email.html", subject=subject, body=body)
