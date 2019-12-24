import os
import mmap

class Mystery:
    def __init__(self, fname):
        fs = os.path.getsize(fname)
        fd = os.open(fname, os.O_RDONLY)
        end = b'IEND'

        self.map = mmap.mmap(fd, fs, access=mmap.ACCESS_READ)
        self.buffer = self.map[self.map.find(end) + len(end) + 4:]  # CRC length = 4
        self.offset = 0

    def read_byte(self):
        byte = self.buffer[self.offset]
        self.offset += 1
        return byte

    def __del__(self):
        self.map.close()


def main():
    # By counting the number of times fputc has been called, the length of
    # the flag should be 26

    flag = [0 for _ in range(26)]
    
    m0_stream = Mystery("mystery.png")
    m1_stream = Mystery("mystery2.png")
    m2_stream = Mystery("mystery3.png")

    flag[1] = m2_stream.read_byte()
    flag[0] = m1_stream.read_byte() - 0x15
    flag[2] = m2_stream.read_byte()
    flag[5] = m2_stream.read_byte()
    flag[4] = m0_stream.read_byte()

    for i in range(6, 10):
        flag[i] = m0_stream.read_byte()

    flag[3] = m1_stream.read_byte() - (10 - 6) * 0x1

    for i in range(10, 0xf):
        flag[i] = m2_stream.read_byte()

    for i in range(0xf, 0x1a):
        flag[i] = m0_stream.read_byte()

    print(''.join(map(chr, flag)))


if __name__ == '__main__':

    main()
