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
except Exception as e:
    raise ImportError("'time' library is a requirement.\r\n{}" .format(e))

try:
    import datetime
except Exception as e:
    raise ImportError("'datetime' library is a requirement.\r\n{}" .format(e))

try:
    import random
except Exception as e:
    raise ImportError("'random' library is a requirement.\r\n{}" .format(e))

try:
    import sys
except Exception as e:
    raise ImportError("'sys' library is a requirement.\r\n{}" .format(e))

try:
    import os
except Exception as e:
    raise ImportError("'os' library is a requirement.\r\n{}" .format(e))

try:
    import requests
except Exception as e:
    raise ImportError("'requests' library is a requirement.\r\n{}" .format(e))

try:
    import pathlib
except Exception as e:
    raise ImportError("'pathlib' library is a requirement.\r\n{}" .format(e))

try:
    import hashlib
except Exception as e:
    raise ImportError("'hashlib' library is a requirement.\r\n{}" .format(e))

try:
    import urllib
except Exception as e:
    raise ImportError("'urllib' library is a requirement.\r\n{}" .format(e))

try:
    import subprocess
except Exception as e:
    raise ImportError("'subprocess' library is a requirement.\r\n{}" .format(e))

try:
    import platform
except Exception as e:
    raise ImportError("'platform' library is a requirement.\r\n{}" .format(e))

# Detecting Python 3 for version-dependent implementations
if sys.version_info.major < 3:
    raise Exception("Python's major versions earlier than 3 are not supported!")

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

#if not os.geteuid() == 0:
#    ___Exception("root privileges is a requirement to run this script...")

###
BASEDIR_PATH = os.path.dirname(os.path.realpath(__file__))
CACHE_PATH = os.path.expanduser('~' + os.sep +'.cache')
TMP_PATH = os.path.expanduser('~' + os.sep + '.tmp')

def main(args):
    # Whitelist
    TargetStatus = None
    AllowedEntries = None
    CollectedEntries = None
    time.sleep(0.5)
    try:
        AllowedF = open(BASEDIR_PATH + os.sep + '.allowlist', 'r')
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
        BlockedF = open(BASEDIR_PATH + os.sep + '.blocklist', 'r')
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
    time.sleep(0.5)
    for root, dirnames, filenames in os.walk(BASEDIR_PATH +  os.sep + 'blocksets'):
        for filename in filenames:
            print(filename)
            try:
                 BlockedF = open(BASEDIR_PATH + os.sep + 'blocksets'+ os.sep + filename, 'r')
            except Exception as e:
                 print("Sorry, something went wrong\r\n" + e)
                 TargetStatus = 0
            else:
                 BlockedEntries = BlockedF.readline()
                 if not BlockedF.closed:
                     BlockedF.close()
                 TargetStatus = 1

    return TargetStatus

try:
    if __name__ == '__main__':
        sys.exit(main(sys.argv))
except KeyboardInterrupt:
    print('Exiting...')
except Exception as e:
    print("Sorry, something went wrong\r\n" + e)

