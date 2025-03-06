#!/usr/bin/env python3

import unittest
from tmc import points
from tmc.utils import load, get_out

import random


key = [76, 60, 3, 12, 228, 108, 217, 230, 58, 206, 91, 249, 138, 45, 28, 195, 244, 133, 40, 27, 44, 222, 139, 5, 103, 80, 232, 173, 23, 86, 157, 52, 4, 156, 81, 56, 22, 246, 183, 131, 149, 41, 51, 110, 119, 2, 114, 151, 141, 33, 158, 252, 61, 248, 152, 178, 200, 255, 123, 85, 18, 121, 34, 189, 1, 184, 171, 13, 202, 175, 46, 211, 194, 127, 197, 35, 98, 170, 0, 219, 11, 236, 137, 30, 229, 218, 142, 64, 168, 48, 181, 115, 94, 135, 180, 74, 134, 68, 251, 116, 59, 237, 150, 89, 9, 87, 188, 253, 164, 231, 216, 96, 220, 130, 199, 43, 174, 191, 92, 77, 117, 208, 239, 75, 57, 104, 214, 148, 29, 72, 15, 190, 153, 250, 192, 147, 225, 6, 210, 126, 93, 176, 32, 111, 113, 187, 14, 97, 146, 129, 90, 163, 198, 144, 66, 107, 124, 226, 172, 196, 102, 167, 47, 182, 71, 49, 120, 215, 165, 161, 125, 39, 69, 166, 101, 78, 31, 21, 65, 8, 245, 233, 136, 243, 162, 84, 179, 20, 160, 122, 38, 70, 62, 63, 242, 7, 55, 254, 204, 10, 95, 155, 213, 67, 224, 186, 159, 99, 25, 26, 53, 209, 128, 185, 193, 169, 177, 54, 79, 227, 50, 37, 73, 240, 16, 100, 105, 36, 247, 207, 241, 143, 82, 132, 238, 112, 145, 109, 212, 118, 106, 140, 221, 203, 201, 223, 234, 235, 83, 88, 154, 17, 42, 205, 24, 19]

module_name="src.substitution"
encode = load(module_name, "encrypt")
decode = load(module_name, "decrypt")


@points('3.2.1', '3.2.2', '3.2.3', '3.2.4', '3.2.5')
class SubstitutionTester(unittest.TestCase):

	def test_simple(self):
		msg = "the quick brown fox jumps over the lazy dog".encode()
		base = bytearray([174, 9, 237, 4, 130, 191, 87, 116, 253, 4, 251, 199, 96, 77, 216, 4, 150, 96, 117, 4, 188, 191, 231, 220, 43, 4, 96, 92, 237, 199, 4, 174, 9, 237, 4, 164, 68, 239, 208, 4, 59, 96, 89])
		cipher = encode(msg, key)
		self.assertEqual(list(cipher), list(base))

		decoded = decode(cipher, key)
		self.assertEqual(msg, decoded)

	def test_scrambled(self):
		msg = "the quick brown fox jumps over the lazy dog".encode()
		base = bytearray([174, 9, 237, 4, 130, 191, 87, 116, 253, 4, 251, 199, 96, 77, 216, 4, 150, 96, 117, 4, 188, 191, 231, 220, 43, 4, 96, 92, 237, 199, 4, 174, 9, 237, 4, 164, 68, 239, 208, 4, 59, 96, 89])

		shuffle = list(range(len(msg)))
		random.shuffle(shuffle)
		msg = bytearray([msg[i] for i in shuffle])
		base = bytearray([base[i] for i in shuffle])

		cipher = encode(msg, key)
		self.assertEqual(list(cipher), list(base))

		decoded = decode(cipher, key)
		self.assertEqual(msg, decoded)
