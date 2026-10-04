"""pickle_loads_request (CWE-502) - bad variant.

Generated benchmark file. The bad variant is the vulnerable form of this scenario.
"""
import pickle

from flask import request


def load_state():
    return pickle.loads(request.get_data())
