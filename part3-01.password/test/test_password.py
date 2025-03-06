#!/usr/bin/env python3

import unittest
from tmc import points
from tmc.utils import load, get_out

import random


module_name="src.hackpassword"
test_password = load(module_name, "test_password")


@points('3.1.1', '3.1.2', '3.1.3', '3.1.4', '3.1.5')
class PasswordTester(unittest.TestCase):

	def test_monkey(self):
		candidates = ['badger', 'boar', 'monkey', 'goa', 'bear', 'gorilla']
		passwd = test_password('42$YmFuYW5h$8HCFgHe9KAUIQ2FSzDQBXqAduyC9U70MOQ83HTfZKGubFKmONnGZLPzGBThiYeDI', candidates)
		self.assertEqual(passwd, 'monkey')

	def test_badger(self):
		candidates = ['badger', 'boar', 'monkey', 'goa', 'bear', 'gorilla']
		passwd = test_password('42$cHl0aG9u$JQrvRSZk/xPIm6pfSfjoG8Jgb9JT5c1nnUtg6vs6QCHn+AR9lhH27PkmB3oeuN9u', candidates)
		self.assertEqual(passwd, 'badger')
