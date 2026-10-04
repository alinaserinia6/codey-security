"""yaml_load_unsafe (CWE-502) - good variant.

Generated benchmark file. The good variant is the repaired form of this scenario.
"""
import yaml


def parse_config(raw):
    return yaml.safe_load(raw)
