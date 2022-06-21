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
# Last Edit: 2022/6/21 09:44:27
#

try:
    import time
except ImportError as e:
    raise ImportError("built-in 'time' library is a requirement.\r\n{}" .format(e))

try:
    import datetime
except ImportError as e:
    raise ImportError("built-in 'datetime' library is a requirement.\r\n{}" .format(e))

try:
    import random
except ImportError as e:
    raise ImportError("built-in 'random' library is a requirement.\r\n{}" .format(e))

try:
    import sys
except ImportError as e:
    raise ImportError("built-in 'sys' library is a requirement.\r\n{}" .format(e))

try:
    import os
except ImportError as e:
    raise ImportError("built-in 'os' library is a requirement.\r\n{}" .format(e))

try:
    import requests
except ImportError as e:
    raise ImportError("built-in 'requests' library is a requirement.\r\n{}" .format(e))

try:
    import pathlib
except ImportError as e:
    raise ImportError("built-in 'pathlib' library is a requirement.\r\n{}" .format(e))

try:
    import hashlib
except ImportError as e:
    raise ImportError("built-in 'hashlib' library is a requirement.\r\n{}" .format(e))

try:
    import urllib
except ImportError as e:
    raise ImportError("built-in 'urllib' library is a requirement.\r\n{}" .format(e))

try:
    import subprocess
except ImportError as e:
    raise ImportError("built-in 'subprocess' library is a requirement.\r\n{}" .format(e))

try:
    import platform
except ImportError as e:
    raise ImportError("built-in 'platform' library is a requirement.\r\n{}" .format(e))

# Detecting Python 3 for version-dependent implementations
if sys.version_info.major < 3:
    raise Exception("Python's major versions earlier than 3 is not supported!")

#cooldown()

def ___Exception(msg):
    print('Exception: {}' .format(msg))
    sys.exit(0)

# Checking whether it isn't Linux...
if platform.uname().system != 'Linux':
   ___Exception("either your OS nor Kernel is unsupported...")

# Checking for sudo's' existance....
try:
    proc = subprocess.Popen("/usr/bin/env bash -c 'command -p sudo'", shell=True, stdout=subprocess.PIPE)
except subprocess.CalledProcessError as err:
    ___Exception( 'ERROR:', err)
else:
    if 'command not found' in proc.stdout.read().decode('utf-8'):
         ___Exception("sudo command doesn't exist!'")

if not os.geteuid() == 0:
    ___Exception("root privileges is a requirement to run this script...")

###
BASEDIR_PATH = os.path.dirname(os.path.realpath(__file__))
CACHE_PATH = os.path.expanduser('~' + os.sep +'.cache')
TMP_PATH = os.path.expanduser('~' + os.sep + '.tmp')

def main():
    # Whitelist
    AllowedEntries = None
    TargetStatus = None
    time.sleep(0.5)
    try:
        AllowedF = open(BASEDIR_PATH +  os.sep + '.allowlist', 'r')
    except FileNotFoundError:
        print("Sorry!")
        TargetStatus = 0
    except Exception as e:
        print("Sorry, something went wrong\r\n" + e)
        TargetStatus = 0
    else:
        AllowedEntries = AllowedF.readline()
        if not AllowedF.closed:
            AllowedF.close()
        TargetStatus = 1

    # Blacklist
    BlockedEntries = None
    time.sleep(0.5)
    try:
        BlockedF = open(BASEDIR_PATH +  os.sep + '.blocklist', 'r')
    except FileNotFoundError:
        print("Sorry!")
        TargetStatus = 0
    except Exception as e:
        print("Sorry, something went wrong\r\n" + e)
        TargetStatus = 0
    else:
        BlockedEntries = BlockedF.readline()
        if not BlockedF.closed:
            BlockedF.close()
        TargetStatus = 1
    
    # Blocksets
    for root, dirnames, filenames in os.walk(BASEDIR_PATH +  os.sep + 'blocksets'):
        for filename in filenames:
            print(filename)
    
    return TargetStatus

if __name__ == '__main__':
    sys.exit(main())

