#!/usr/bin/env python3

import unittest
from tmc import points
from tmc.utils import load, get_out

import random



module_name="src.xorpad"
encode = load(module_name, "encrypt")
decode = load(module_name, "decrypt")


@points('3.4.1', '3.4.2', '3.4.3', '3.4.4', '3.4.5')
class XorPadTester(unittest.TestCase):

	def test_simple(self):
		msg = "the quick brown fox jumps over the lazy dog".encode()
		pad = "foobar".encode()
		base = bytearray([18, 7, 10, 66, 16, 7, 15, 12, 4, 66, 3, 0, 9, 24, 1, 66, 7, 29, 30, 79, 5, 23, 12, 2, 21, 79, 0, 20, 4, 0, 70, 27, 7, 7, 65, 30, 7, 21, 22, 66, 5, 29, 1])
		cipher = encode(msg, pad)
		self.assertEqual(cipher, base)

		decoded = decode(cipher, pad)
		self.assertEqual(msg, decoded)

	def test_scrambled(self):
		msg = "the quick brown ox jumps over the lazy dog".encode()
		pad = "foobar".encode()
		base = bytearray([18, 7, 10, 66, 16, 7, 15, 12, 4, 66, 3, 0, 9, 24, 1, 66, 14, 10, 70, 5, 26, 15, 17, 1, 70, 0, 25, 7, 19, 82, 18, 7, 10, 66, 13, 19, 28, 22, 79, 6, 14, 21])

		shuffle = list(range(7))
		random.shuffle(shuffle)
		msg = bytearray([x for i in shuffle for x in msg[i*6:(i+1)*6]])
		base = bytearray([x for i in shuffle for x in base[i*6:(i+1)*6]])

		cipher = encode(msg, pad)
		self.assertEqual(cipher, base)

		decoded = decode(cipher, pad)
		self.assertEqual(msg, decoded)
