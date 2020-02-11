__author__ = 'Devon Chen'

# FLAG = picoCTF{d0Nt_r0ll_yoUr_0wN_aES}

BLOCK_SIZE = 16
UMAX = 256 ** BLOCK_SIZE

if __name__ == '__main__':

    f = open('body.enc.ppm', 'rb')

    data = f.read()
    header = b''
    for _ in range(3):
        i = data.find(b'\n')
        header += data[0:i+1]
        data = data[i+1:]

    blocks = [int(data[i:i+BLOCK_SIZE].hex(), 16) for i in range(0, len(data), BLOCK_SIZE)]
    blocks = [(blocks[i+1] - blocks[i]) % UMAX for i in range(len(blocks) - 1)]
    for i in range(len(blocks)):
        s = format(blocks[i], 'x')
        if len(s) % 2 != 0:
            s = '0' + s
        blocks[i] = bytes.fromhex(s)

    with open('flag.ppm', 'wb') as flag:
        flag.write(header)
        flag.write(b''.join(blocks))

    f.close()