"""shutil_rmtree_user (CWE-22) - bad variant.

Generated benchmark file. The bad variant is the vulnerable form of this scenario.
"""
import shutil


def clean_workspace(folder):
    shutil.rmtree(folder)
