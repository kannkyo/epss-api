import subprocess
import logging


def main():
    cmd = [
        ["git", "push", "--follow-tags", "-f", "origin", "main"]
    ]

    for c in cmd:
        try:
            ret = subprocess.run(c)
            logging.info(ret.stdout)
        except subprocess.TimeoutExpired as e:
            logging.error(ret.stderr)
            logging.error(f'timeout = {e.timeout}')
        except subprocess.CalledProcessError as e:
            logging.error(ret.stderr)
            logging.error(f'returncode = {e.returncode}')
            logging.error(f'output = {e.output}')
