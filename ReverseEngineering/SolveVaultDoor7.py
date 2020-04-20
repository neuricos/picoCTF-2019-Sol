#!/usr/bin/env python3

xs = [1096770097, 1952395366, 1600270708, 1601398833, 1716808014, 1734304823, 962880562, 895706419]
flag = ""
for x  in xs:
    ss = [8 * i for i in reversed(range(4))]
    ms = [0xFF << s for s in ss]
    vs = [(ms[i] & x) >> ss[i] for i in range(len(ss))]
    us = [chr(int(hex(v), 16)) for v in vs]
    flag += "".join(us)
print(flag)
