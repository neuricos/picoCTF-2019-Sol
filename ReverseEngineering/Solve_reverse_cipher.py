#!/usr/bin/env python3

f = open("rev_this", "r")

flag = ""
modified_flag = f.readline().strip()

# Keep the first 8 chars to be the same

flag += modified_flag[:8]

# For index from 8 to 22, change the value back to the original

for i in range(8, 23):
    if i % 2 == 0:
        flag += chr(ord(modified_flag[i]) - 0x5)
    else:
        flag += chr(ord(modified_flag[i]) + 2)

# Add the last char

flag += modified_flag[-1]

f.close()

print(flag)

