import subprocess
import logging


def main():
    cmd = ["cyclonedx-py", "-e", "--force",
           "--format", "xml",
           "-o", "sbom.xml"]

    try:
        ret = subprocess.run(cmd)
        logging.info(ret.stdout)
    except subprocess.TimeoutExpired as e:
        logging.error(ret.stderr)
        logging.error(f'timeout = {e.timeout}')
    except subprocess.CalledProcessError as e:
        logging.error(ret.stderr)
        logging.error(f'returncode = {e.returncode}')
        logging.error(f'output = {e.output}')
