#!/usr/bin/env python3

s = "jU5t_a_sna_3lpm16g84c_u_4_m0r846"

d = {}

for i in range(8):
    d[i] = s[i]

for i in range(8, 16):
    j = 23 - i
    d[j] = s[i]

for i in range(16, 32, 2):
    j = 46 - i
    d[j] = s[i]

for i in range(31, 16, -2):
    d[i] = s[i]

flag = "".join([d[i] for i in range(max(d) + 1)])

print(flag)
