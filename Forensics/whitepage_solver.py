with open('whitepages.txt', 'rb') as f:
    data = f.read()

data = data.replace(b'\xe2\x80\x83', b'0')
data = data.replace(b'\x20', b'1')

value = format(int(data, 2), 'x')
if len(value) % 2 == 1:
    value = '0' + value
value = bytes.fromhex(value)

chars = [value[2*i:2*i+2] for i in range(len(value) // 2)]

print(b''.join(chars).decode('utf-8'))