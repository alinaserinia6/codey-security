"""render_template_string_argv (CWE-1336) - bad variant.

Generated benchmark file. The bad variant is the vulnerable form of this scenario.
"""
from flask import render_template_string


def render_greeting(name):
    return render_template_string("Hello " + name)
