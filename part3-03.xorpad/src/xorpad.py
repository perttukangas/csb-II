#!/usr/bin/env python3
import sys
import socket


def encrypt(msg, pad):
    # both msg and pad are byte arrays
    ciphertext = bytearray(len(msg))

    # write code here
    for i in range(len(msg)):
        # As for "can you figure out how?" if attacker happens to know first 5 chars of plain text
        # and the padding is 5 chars, the attacker can just xor first 5 chars
        # to get the 'pad' and then decrypt the whole message.
        ciphertext[i] = msg[i] ^ pad[i % len(pad)]

    return ciphertext


def decrypt(ciphertext, pad):
    # both msg and pad are byte arrays
    msg = bytearray(len(ciphertext))

    # write code here
    for i in range(len(ciphertext)):
        msg[i] = ciphertext[i] ^ pad[i % len(pad)]

    return msg


def main(argv):
    msg = argv[1]
    pad = argv[2]

    print("Plain message:")
    print(msg)
    print("\nPad:")
    print(pad)

    cipher = encrypt(msg.encode(), pad.encode())

    print("\nCipher text (as integer array):")
    print(list(cipher))

    decoded = decrypt(cipher, pad.encode())

    print("\nDecoded text (as integer array):")
    print(list(decoded))
    print("\nDecoded plain text:")
    print(decoded.decode())


# This makes sure the main function is not called immediatedly
# when TMC imports this module
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: python %s msg pad" % sys.argv[0])
    else:
        main(sys.argv)
