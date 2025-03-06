#!/usr/bin/env python3
import sys
import socket

import random


def encrypt(msg, key):
    # both msg and key are byte arrays
    ciphertext = bytearray(len(msg))

    # write code here
    for i in range(len(msg)):
        ciphertext[i] = key[msg[i]]

    return ciphertext


def decrypt(ciphertext, key):
    # both msg and key are byte arrays
    msg = bytearray(len(ciphertext))

    # write code here
    for i in range(len(ciphertext)):
        msg[i] = key.index(ciphertext[i])

    return msg


def main(argv):
    msg = argv[1]

    if len(argv) >= 3:
        random.seed(int(argv[2]))

    key = bytearray(range(256))
    random.shuffle(key)

    print("Plain message:")
    print(msg)
    print("\nkey:")
    print(list(key))

    cipher = encrypt(msg.encode(), key)

    print("\nCipher text (as integer array):")
    print(list(cipher))

    decoded = decrypt(cipher, key)

    print("\nDecoded text (as integer array):")
    print(list(decoded))
    print("\nDecoded plain text:")
    print(decoded.decode())


# This makes sure the main function is not called immediatedly
# when TMC imports this module
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: python %s msg [random seed]" % sys.argv[0])
    else:
        main(sys.argv)
