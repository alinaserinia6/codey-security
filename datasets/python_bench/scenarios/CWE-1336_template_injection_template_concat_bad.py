"""template_concat (CWE-1336) - bad variant.

Generated benchmark file. The bad variant is the vulnerable form of this scenario.
"""
from jinja2 import Template


def render_email(subject, body):
    return Template("<p>" + subject + "</p><p>" + body + "</p>").render()
