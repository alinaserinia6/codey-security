"""yaml_load_unsafe (CWE-502) - bad variant.

Generated benchmark file. The bad variant is the vulnerable form of this scenario.
"""
import yaml


def parse_config(raw):
    return yaml.load(raw)
