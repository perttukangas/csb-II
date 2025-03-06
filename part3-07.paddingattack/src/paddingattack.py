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


# Use Cbc from the CBC exercise
# add function decode_padded that is the same as decode but doesn't remove padding
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

    def decode_padded(self, cipher, iv):
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

        return results

    def decode(self, cipher, iv):
        # cipher is a byte array
        # iv is an initilization vector for cbc (byte array of length 8)
        # use self.block.decode() the blocks are length 8

        results = self.decode_padded(cipher, iv)

        padding = results[-1]
        results = results[:-padding]

        return results


class PaddingOracle:
    def __init__(self, cbc):
        self.cbc = cbc

    # tells is the cipher ends with the correct padding
    def isvalid(self, b1, b2):
        plain = self.cbc.decode_padded(b2, b1)  # b1 acts as iv
        padlen = plain[-1]
        if padlen > 8:
            return False
        return plain[-padlen:] == bytearray([padlen for i in range(padlen)])


# finds a valid padding in b2 by manipulating b1[index]
# b1 and b2 are bytearrays of length 8
# you have to deal with the speacial case when len(valid_values) == 2
# b1 should be given as iv to oracle (note the parameter order)
def test_value(b1, b2, index, oracle):
    valid_values = []
    m = b1[:]  # create a copy that we can modify without changing b1

    for i in range(256):
        m[index] = i
        if oracle.isvalid(m, b2):
            valid_values.append(i)

    if len(valid_values) == 2:
        m[index] = valid_values[0]
        m[index - 1] = (m[index - 1] + 1) % 256
        if not oracle.isvalid(m, b2):
            return valid_values[1]

    return valid_values[0]


# decodes b2 by manipulating b1
# b1 and b2 are bytearrays of length 8
def decode_block(b1, b2, oracle):
    # output of the decoder _before_ xor with the previous cipher block
    d = bytearray(8)

    # decoded block
    plain = bytearray(8)

    m = bytearray(8)

    for i in range(8):
        cur_pos = 8 - i - 1

        for j in range(cur_pos, 8):
            m[j] = d[j] ^ (i + 1)

        test_val = test_value(m, b2, cur_pos, oracle)

        d[cur_pos] = test_val ^ (i + 1)

        plain[cur_pos] = b1[cur_pos] ^ d[cur_pos]

    return plain


def padding_attack(cipher, iv, oracle):
    plain = bytearray(len(cipher))

    # decode all blocks except the first block
    for i in range(8, len(cipher), 8):
        plain[i : (i + 8)] = decode_block(
            cipher[(i - 8) : i], cipher[i : (i + 8)], oracle
        )

    plain[0:8] = decode_block(iv, cipher[0:8], oracle)

    return plain


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

    oracle = PaddingOracle(cbc)

    plain = padding_attack(cipher, iv, oracle)
    print("Padding attack:", plain)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: python %s message rounds" % sys.argv[0])
    else:
        main(sys.argv)
