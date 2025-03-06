#!/usr/bin/env python3
import sys
import socket

import random
from string import ascii_lowercase  # string containing all lower-case alphabets letters


def decode(ciphertext, frequencies):
    # ciphertext is a string, frequencies is a dictionary with entries {letter:  float}

    clear = ""

    # write code here
    cipher_freqs = {}
    for char in ciphertext:
        if char in ascii_lowercase:
            cipher_freqs[char] = cipher_freqs.get(char, 0) + 1

    sorted_cipher_freq = sorted(
        cipher_freqs.keys(), key=lambda x: cipher_freqs[x], reverse=True
    )
    sorted_freq = sorted(frequencies.keys(), key=lambda x: frequencies[x], reverse=True)

    for i in range(len(ciphertext)):
        if ciphertext[i].islower():
            for j, cipher_char in enumerate(sorted_cipher_freq):
                if cipher_char == ciphertext[i]:
                    clear += sorted_freq[j]
                    break
        else:
            clear += ciphertext[i]

    return clear
