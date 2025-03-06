#!/usr/bin/env python3

import unittest
from tmc import points
from tmc.utils import load, get_out

import uuid
import http.server as hs
import requests
import time

from threading import Thread

module_name="src.mitm"
Mitm = load(module_name, "Mitm")


class SimpleHandler(hs.BaseHTTPRequestHandler):
	content = None
	def do_GET(self):
		if self.path == '/foo.html':
			self.send_response(200)
			self.send_header("Content-type", "text/html")
			self.end_headers()
			self.wfile.write(self.content.encode()) 
		elif self.path == '/foo.txt':
			self.send_response(200)
			self.send_header("Content-type", "text/plain")
			self.end_headers()
			self.wfile.write(self.content.encode()) 
		else:
			self.send_response(404)
			self.send_header("Content-type", "text/plain")
			self.end_headers()
			self.wfile.write('Not found'.encode()) 


@points('3.8.1', '3.8.2', '3.8.3', '3.8.4', '3.8.5')
class MitmTester(unittest.TestCase):

	def test_mitm(self):
		c = str(uuid.uuid4()).lower()
		SimpleHandler.content = c

		target = hs.HTTPServer(("localhost", 0), SimpleHandler)
		thread = Thread(target=target.serve_forever)
		thread.daemon = True
		thread.start()

		time.sleep(0.5) # give some time for the server to spin up

		target_port = target.server_port

		Mitm.remote_address = "http://localhost:" + str(target_port)
		mitm = hs.HTTPServer(("localhost", 0), Mitm)
		thread = Thread(target=mitm.serve_forever)
		thread.daemon = True
		thread.start()

		time.sleep(0.5) # give some time for the server to spin up
		
		mitm_port = mitm.server_port
		address = 'http://localhost:' + str(mitm_port)

		response = requests.get(address + '/foo.html')
		self.assertEqual(response.status_code, 200, "Status code is not set properly")
		self.assertEqual(response.headers.get('Content-type', ''), 'text/html', "Content-type is not set properly")
		self.assertIn(c.upper(), response.text, "text is not correct for html file.")

		response = requests.get(address + '/foo.txt')
		self.assertEqual(response.status_code, 200, "Status code is not set properly")
		self.assertEqual(response.headers.get('Content-type', ''), 'text/plain', "Content-type is not set properly")
		self.assertIn(c, response.text, "text is not correct for plain text file.")

		response = requests.get(address + '/doesnotexist')
		self.assertEqual(response.status_code, 404, "Status code is not set properly")
		self.assertEqual(response.headers.get('Content-type', ''), 'text/plain', "Content-type is not set properly")
