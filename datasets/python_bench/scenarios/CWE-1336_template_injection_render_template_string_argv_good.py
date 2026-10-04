"""render_template_string_argv (CWE-1336) - good variant.

Generated benchmark file. The good variant is the repaired form of this scenario.
"""
from flask import render_template


def render_greeting(name):
    return render_template("greeting.html", name=name)
