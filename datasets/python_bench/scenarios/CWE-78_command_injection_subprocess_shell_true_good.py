"""subprocess_shell_true (CWE-78) - good variant.

Generated benchmark file. The good variant is the repaired form of this scenario.
"""
import subprocess
import sys


def run_user_command(command):
    subprocess.call(command.split(), shell=False)


if __name__ == "__main__":
    run_user_command(sys.argv[1])
