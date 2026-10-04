"""shutil_rmtree_user (CWE-22) - good variant.

Generated benchmark file. The good variant is the repaired form of this scenario.
"""
import os
import shutil


def clean_workspace(folder):
    root = os.path.abspath("/var/workspaces")
    target = os.path.abspath(os.path.join(root, os.path.basename(folder)))
    if os.path.commonpath([root, target]) == root:
        shutil.rmtree(target)
