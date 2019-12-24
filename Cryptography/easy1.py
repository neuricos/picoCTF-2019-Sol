t = {}
for i in range(ord('A'), ord('Z') + 1):
    k1 = chr(i)
    for j in range(i, i + 26):
        k2 = chr((j - i) + ord('A'))
        c = chr(((j - ord('A')) % 26) + ord('A'))
        t[(k1, k2)] = c

key = "SOLVECRYPTO"
msg = "UFJKXQZQUNB"

flag = ""

for i in range(len(msg)):
    for v in range(ord('A'), ord('Z') + 1):
        if t[(chr(v), key[i])] == msg[i]:
            flag += chr(v)
            continue

print(flag)
