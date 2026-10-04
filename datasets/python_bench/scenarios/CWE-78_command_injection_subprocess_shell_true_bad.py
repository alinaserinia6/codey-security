"""subprocess_shell_true (CWE-78) - bad variant.

Generated benchmark file. The bad variant is the vulnerable form of this scenario.
"""
import subprocess
import sys


def run_user_command(command):
    subprocess.call(command, shell=True)


if __name__ == "__main__":
    run_user_command(sys.argv[1])
