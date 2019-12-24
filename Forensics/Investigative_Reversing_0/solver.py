data = "70 69 63 6F 43 54 4B 80 6B 35 7A 73 69 64 36 71 5F 39 64 65 30 33 30 35 30 7D"
arr = bytearray(bytes.fromhex(data.replace(' ', '')))
for i in range(6, 0xf):
    arr[i] = arr[i] - 0x5
arr[0xf] = arr[0xf] + 3
print(arr)
