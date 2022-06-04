#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#  main.py
#
#  Copyright 2022 John Magdy Lotfy Kamel (Zorono) <johnmagdy437@yahoo.com>
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#
# Last Edit: 2022/05/20 13:51:37
#

try:
    import time
except ImportError:
    raise ImportError("built-in 'time' library is a requirement.")

try:
    import datetime
except ImportError:
    raise ImportError("built-in 'datetime' library is a requirement.")

try:
    import random
except ImportError:
    raise ImportError("built-in 'random' library is a requirement.")

try:
    import sys
except ImportError:
    raise ImportError("built-in 'sys' library is a requirement.")

try:
    import os
except ImportError:
    raise ImportError("built-in 'os' library is a requirement.")

try:
    import requests
except ImportError:
    raise ImportError("built-in 'requests' library is a requirement.")

try:
    import pathlib
except ImportError:
    raise ImportError("built-in 'pathlib' library is a requirement.")

try:
    import hashlib
except ImportError:
    raise ImportError("built-in 'hashlib' library is a requirement.")

try:
    import urllib
except ImportError:
    raise ImportError("built-in 'urllib' library is a requirement.")

try:
    import subprocess
except ImportError:
    raise ImportError("built-in 'subprocess' library is a requirement.")

try:
    import platform
except ImportError:
    raise ImportError("built-in 'platform' library is a requirement.")

# Detecting Python 3 for version-dependent implementations
if sys.version_info.major < 3:
    raise Exception("Python's major versions earlier than 3 is not supported!")

#cooldown()

# Checking whether it isn't Linux...
if platform.uname().system != 'Linux':
   raise Exception("either your OS nor Kernel is unsupported...")

# Checking for sudo's' existance....
proc = subprocess.Popen([
    "/usr/bin/env", "command", "-p", "sudo"
], stdout=subprocess.PIPE)

if 'command not found' in proc.stdout.read():
   raise Exception("sudo command doesn't exist!'")

###
BASEDIR_PATH = os.path.dirname(os.path.realpath(__file__))
CACHE_PATH = os.path.expanduser('~' + os.sep +'.cache')
TMP_PATH = os.path.expanduser('~' + os.sep + '.tmp')

def usage():
    print("Usage: " + sys.argv[0] + " <arg1> <arg2> <arg3>")

def main(args):
    print(len(args))
    if len(args) != 4:
        usage()
        return 0
    else:
        parse(args[1], int(args[2]), int(args[3]))
        time.sleep(1)
        return 1

if __name__ == '__main__':
    sys.exit(main(sys.argv))

