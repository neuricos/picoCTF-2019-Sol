#!/usr/bin/env python3

# Input file should be VaultDoor1.java

import sys, re

if len(sys.argv) != 2:
    print("Please specify input file", file=sys.stderr)
    sys.exit(1)

f = open(sys.argv[1], 'r')

lines = filter(lambda l: "password.charAt" in l, f.readlines())

d = {}

for line in lines:
    i, c = re.findall(r"password\.charAt\((\d+)\)\s*==\s*'(\w)'", line)[0]
    d[int(i)] = c

flag = "".join([d[i] for i in range(max(d) + 1)])

print(flag)

f.close()
