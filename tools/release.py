import subprocess
import logging
import toml
import sys
from os import path

cwd = path.join(path.dirname(path.abspath(__file__)), path.pardir)


def exe(cmd: list):
    ret = subprocess.run(cmd, cwd=cwd)
    logging.info(cmd)
    logging.info(ret.stdout)
    return ret


def main():
    try:
        # change version
        if len(sys.argv) == 2:
            option = sys.argv[1]
            ret = exe(['poetry', 'version', option])
        elif len(sys.argv) > 2:
            raise Exception('wrong argument ' + sys.argv)

        # get version
        project = toml.load(path.join(cwd, 'pyproject.toml'))
        version = 'v' + project['tool']['poetry']['version']

        # generate tag
        ret = exe(['git', 'add', 'pyproject.toml'])
        ret = exe(['git', 'commit', '-S', '-m', version])
        ret = exe(['git', 'tag', '-s', version, '-m', version])
    except subprocess.TimeoutExpired as e:
        logging.error(ret.stderr)
        logging.error(f'timeout = {e.timeout}')
    except subprocess.CalledProcessError as e:
        logging.error(ret.stderr)
        logging.error(f'returncode = {e.returncode}')
        logging.error(f'output = {e.output}')
    except Exception as e:
        logging.error(e)
