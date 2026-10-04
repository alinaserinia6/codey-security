"""jinja_from_string (CWE-1336) - bad variant.

Generated benchmark file. The bad variant is the vulnerable form of this scenario.
"""
from jinja2 import Template


def render_profile(profile):
    return Template(profile).render()
