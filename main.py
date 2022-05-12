#!/usr/bin/env python3

import time
import random
import sys

WHITELIST=./.allowlist
BLACKLIST=./blocklist

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
