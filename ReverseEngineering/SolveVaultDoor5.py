#!/usr/bin/env python3

import base64

s = "JTYzJTMwJTZlJTc2JTMzJTcyJTc0JTMxJTZlJTY3JTVmJTY2JTcyJTMwJTZkJTVmJTYyJTYxJTM1JTY1JTVmJTM2JTM0JTVmJTY0JTYxJTM4JTM4JTMyJTY0JTMwJTMx"
urlEncoded = base64.b64decode(s)
urlEncoded_list = [urlEncoded[i:i+3] for i in range(0, len(urlEncoded), 3)]
byte_list = [int(sym[1:], 16) for sym in urlEncoded_list]
char_list = [chr(b) for b in byte_list]
flag = "".join(char_list)
print(flag)
