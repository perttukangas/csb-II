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


# Use class from Feistel exercise
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


# XORs two bytearrays of same legth
def xor(a, b):
    return bytearray([x ^ y for x, y in zip(a, b)])


class Cbc:
    def __init__(self, block):
        self.block = block

    def encode(self, plain, iv):
        # plain is a byte array
        # iv is an initilization vector for cbc (byte array of length 8)
        # use self.block.encode() the blocks are length 8

        padding = 8 - len(plain) % 8
        if padding == 0:
            padding = 8
        plain += bytes([padding] * padding)

        prev = iv
        results = bytearray()

        for i in range(0, len(plain), 8):
            block = plain[i : i + 8]
            encrypted_block = self.block.encode(xor(block, prev))
            results += encrypted_block
            prev = encrypted_block

        return results

    def decode(self, cipher, iv):
        # cipher is a byte array
        # iv is an initilization vector for cbc (byte array of length 8)
        # use self.block.decode() the blocks are length 8

        prev = iv
        results = bytearray()

        for i in range(0, len(cipher), 8):
            block = cipher[i : i + 8]
            decrypted_block = xor(prev, self.block.decode(block))
            results += decrypted_block
            prev = block

        padding = results[-1]
        results = results[:-padding]

        return results


def main(argv):
    sbox = [[random.getrandbits(32) for r in range(256)] for i in range(4)]
    hasher = Hasher(sbox)

    keys = [random.getrandbits(32).to_bytes(4, "little") for i in range(int(argv[2]))]
    f = Feistel(keys, hasher.transform)

    cbc = Cbc(f)

    iv = bytearray(8)
    msg = argv[1]
    print("Message:", msg)

    cipher = cbc.encode(msg.encode(), iv)
    print("After encoding:", cipher)

    plain = cbc.decode(cipher, iv)
    print("After decoding:", plain)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: python %s message rounds" % sys.argv[0])
    else:
        main(sys.argv)
