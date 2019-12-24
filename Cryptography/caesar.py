import sys

def rot3(s):
    def shift(c, forward=True):
        d = 3 if forward else -3

        if c >= 'a' and c <= 'z':
            return chr(((ord(c) - ord('a') + d) % 26) + ord('a'))

        if c >= 'A' and c <= 'Z':
            return chr(((ord(c) - ord('A') + d) % 26) + ord('A'))

        return c

    return ''.join(map(shift, s))


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <string>")
        sys.exit(1)

    print(rot3(sys.argv[1]))


if __name__ == '__main__':
    main()
