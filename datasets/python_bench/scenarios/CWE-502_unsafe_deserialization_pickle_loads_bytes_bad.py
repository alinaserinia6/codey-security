"""pickle_loads_bytes (CWE-502) - bad variant.

Generated benchmark file. The bad variant is the vulnerable form of this scenario.
"""
import pickle


def restore_session(blob):
    return pickle.loads(blob)
