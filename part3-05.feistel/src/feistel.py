import sys
import random


class Hasher:
    def __init__(self, sbox):
        self.sbox = sbox

    def transform(self, key, data):
        # data is an array of size 4
        t = bytearray([key[i] ^ data[i] for i in range(4)])
        h = self.sbox[0][t[0]] + self.sbox[1][t[1]]
        h ^= self.sbox[2][t[2]]
        h += self.sbox[3][t[3]]
        h &= 0xFFFFFFFF  # take care of overflow
        return h.to_bytes(4, "little")


class Feistel:
    def __init__(self, keys, roundf):
        self.keys = keys
        self.roundf = roundf

    def encode(self, plain):
        # plain is an array of length 8
        cipher = bytearray(plain)

        # write code here
        L, R = cipher[:4], cipher[4:]

        for key in self.keys:
            F = self.roundf(key, R)
            tmp_R = R
            R = bytearray([L[i] ^ F[i] for i in range(4)])
            L = tmp_R

        return L + R

    def decode(self, cipher):
        # cipher is a byte array of length 8
        plain = bytearray(cipher)

        # write code here
        L, R = plain[:4], plain[4:]

        for key in reversed(self.keys):
            F = self.roundf(key, L)
            tmp_L = L
            L = bytearray([R[i] ^ F[i] for i in range(4)])
            R = tmp_L

        return L + R


def main(argv):
    sbox = [[random.getrandbits(32) for r in range(256)] for i in range(4)]
    hasher = Hasher(sbox)

    keys = [random.getrandbits(32).to_bytes(4, "little") for i in range(int(argv[2]))]
    f = Feistel(keys, hasher.transform)

    msg = argv[1]
    print("Message:", msg)

    cipher = f.encode(msg.encode())
    print("After encoding:", cipher)

    plain = f.decode(cipher)
    print("After decoding:", plain)


if __name__ == "__main__":
    if len(sys.argv) != 3 or len(sys.argv[1]) != 8:
        print("usage: python %s message rounds" % sys.argv[0])
        print("message should be 8 characters")
    else:
        main(sys.argv)
