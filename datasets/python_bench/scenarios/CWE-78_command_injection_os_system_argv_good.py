"""os_system_argv (CWE-78) - good variant.

Generated benchmark file. The good variant is the repaired form of this scenario.
"""
import os
import sys


def list_directory(path):
    os.system("ls " + os.path.basename(path))


if __name__ == "__main__":
    list_directory(sys.argv[1])
