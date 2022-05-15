#!/usr/bin/env python3

try:
    import time
except ImportError:
    raise ImportError("''time' library is a requirement.")

try:
    import datetime
except ImportError:
    raise ImportError("''datetime' library is a requirement.")

try:
    import random
except ImportError:
    raise ImportError("''random' library is a requirement.")

try:
    import sys
except ImportError:
    raise ImportError("'sys' library is a requirement.")

try:
    import os
except ImportError:
    raise ImportError("''os' library is a requirement.")

try:
    import requests
except ImportError:
    raise ImportError("''requests' library is a requirement.")

try:
    import pathlib
except ImportError:
    raise ImportError("''pathlib' library is a requirement.")

try:
    import hashlib
except ImportError:
    raise ImportError("''hashlib' library is a requirement.")

try: 
    import urllib
except ImportError:
    raise ImportError("''urllib' library is a requirement.")

try:
    import subprocess
except ImportError:
    raise ImportError("''subprocess' library is a requirement.")

import helpers/cooldown

# Detecting Python 3 for version-dependent implementations
if sys.version_info.major < 3:
    raise Exception("Python's' major versions earlier than 3 is not supported!")

cooldown()

# Checking whether it isn't Linux...
if platform.system() != 'Linux':
   raise Exception("either your OS nor Kernel is unsupported...")

# Checking for sudo's' existance....
proc = subprocess.Popen([
    "/usr/bin/env", "command", "-p", "sudo"
], stdout=subprocess.PIPE).stdout.read()

if 'command not found' in proc.stdout.read():
   raise Exception("sudo command doesn't exist!'")

###
BASEDIR_PATH = os.path.dirname(os.path.realpath(__file__))
CACHE_PATH = os.path.expanduser('~' + os.sep +'.cache')
TMP_PATH = os.path.expanduser('~' + os.sep + '.tmp')

def usage():
    print("Usage: " + sys.argv[0] + " <arg1> <arg2> <arg3>")

def main():
    print(len(sys.argv))
    if len(sys.argv) != 4:
        usage()
    else:
        parse(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]))
        time.sleep(1)	

if __name__ == '__main__':
    main()
