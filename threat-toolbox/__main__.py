#from __future__ import (print_function, unicode_literals, division, absolute_import)
__metaclass__ = type
__package_name__ = 'threat-toolbox'

## Standard Libraries
import os
import sys
import argparse
import logging
from pprint import pprint#, pformat

## Third Party libraries
import pkg_resources

## Modules
# try:
#     from .classes import CustomExceptions
# except ImportError:
#     # If we can't import modules, probably running from VSCODE
#     # attempt to hack in modules
#     import importlib
#     SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
#     sys.path.append(os.path.dirname(SCRIPT_DIR))
#     CustomExceptions = importlib.import_module(__package_name__+'.classes.CustomExceptions')

## Load up some metadata
try:
    __code_name__  = __package_name__
    # spacing is deliberate
    __code_desc__ = """ program description to be displayed by argparse \n    ex: python {name}
        """.format(name=str(__package_name__)+'.py')
    _distro = pkg_resources.get_distribution(__package_name__)
    __code_version__ = _distro.version
    __code_meta__ = vars(_distro)
    __code_debug__ = False
except pkg_resources.DistributionNotFound:
    # when debugging with vscode
    __code_debug__ = True
    stubs = [ '__code_version__', '__code_meta__']
    for s in stubs:
        globals()[s] = 'Not Available'

## Functions
def __print_dunders__():
    blacklist = ['__builtins__', '__print_dunders__']
    for k, v in list(globals().items()):
        if k.startswith('__'):
            if k in blacklist:
                pass
            else:
                pprint("%s => %s" % (k, v))

def demo():
    __print_dunders__()
    sys.exit(1)

def begin_logging():
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter(
            style="{",
            fmt="[{name}:{filename}] {levelname} - {message}"
        )
    )
    log = logging.getLogger(__package_name__)
    log.setLevel(logging.INFO)
    log.addHandler(handler)

def collect_args():
    parser = argparse.ArgumentParser(description=__code_desc__,
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-V', '--version', action='version', version=__code_version__)
    parser.add_argument('-v', '--verbose', action='count', default=0)
    args = parser.parse_args()
    return parser, args

def handle_args():
    # collect parser if needed to conditionally call usage: parser.print_help()
    parser, args = collect_args()
    return args

def main():
    begin_logging()
    args = handle_args()

    try:
        return
    except Exception as e:
        pprint(e)
        raise e
    finally:
        pass

if __name__=="__main__":
    main()
