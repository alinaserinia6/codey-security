"""jinja_from_string (CWE-1336) - good variant.

Generated benchmark file. The good variant is the repaired form of this scenario.
"""
from jinja2 import Environment, FileSystemLoader


def render_profile(profile):
    env = Environment(loader=FileSystemLoader("templates"))
    return env.get_template("profile.html").render(name=profile)
