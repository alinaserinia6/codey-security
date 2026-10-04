"""os_system_argv (CWE-78) - bad variant.

Generated benchmark file. The bad variant is the vulnerable form of this scenario.
"""
import os
import sys


def list_directory(path):
    os.system("ls " + path)


if __name__ == "__main__":
    list_directory(sys.argv[1])
