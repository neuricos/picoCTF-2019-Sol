#!/usr/bin/env python3

bs = [0x3b,0x65,0x21,0xa,0x38,0x0,0x36,0x1d,0xa,0x3d,0x61,0x27,0x11,0x66,0x27,0xa,0x21,0x1d,0x61,0x3b,0xa,0x2d,0x65,0x27,0xa,0x65,0x36,0x66,0x34,0x67,0x31,0x30]

flag = "".join([chr(b ^ 0x55) for b in bs])
print(flag)
