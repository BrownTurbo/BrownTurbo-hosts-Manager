#!/usr/bin/env python3

import datetime
import random
import sys
import os

try:
    import requests
except ImportError:
    raise ImportError("The Requests library (https://docs.python-requests.org/en/latest/) is a requirement.")

import pathlib
import hashlib
import urllib2
import urlparse
import subprocess

# Detecting Python 3 for version-dependent implementations
PY3 = sys.version_info >= (3, 0)

if not PY3:
    raise Exception("We do not support Python 2 anymore.")

# Checking whether it isn't Linux...
if platform.system() != 'Linux':
   print("ERROR: Unsupported OS...")
   sys.exit(9)

# Checking for sudo's' existance....
proc = subprocess.Popen([
    "/usr/bin/env", "command", "-p", "sudo"
], stdout=subprocess.PIPE).stdout.read()

if 'command not found' in proc.stdout.read():
   print("ERROR: Sudo command doesn't exist!'")
   sys.exit(9)

###
___dir = os.path.dirname(os.path.realpath(__file__))

def usage():
    print("Usage: " + sys.argv[0] + " <arg1> <arg2> <arg3>")

def main():
    print(len(sys.argv))
    if len(sys.argv) != 4:
        usage()
    else:
        parse(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]))

if __name__ == '__main__':
    main()
