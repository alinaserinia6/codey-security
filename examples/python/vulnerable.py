import subprocess
import sys


def run_user_command(command: str) -> None:
    subprocess.call(command, shell=True)


if __name__ == "__main__" and len(sys.argv) > 1:
    run_user_command(sys.argv[1])
