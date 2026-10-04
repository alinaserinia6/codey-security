"""marshal_loads_file (CWE-502) - bad variant.

Generated benchmark file. The bad variant is the vulnerable form of this scenario.
"""
import marshal


def read_cache(path):
    with open(path, "rb") as handle:
        return marshal.loads(handle.read())
