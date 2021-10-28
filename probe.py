import socket
from util import Util

class Probe():
	def __init__(self, target, port, options, _type=socket.SOCK_STREAM):
		self.type = _type
		self.target = target
		self.port = port
		self.options = options
		self.status = None
		self.socket = socket.socket(socket.AF_INET, _type)

	def refused(self):
		self.status = False
		self.socket.close()

	def receive(self):
		self.status = True
		self.socket.close()
		Util.msg('Found udp port: %d' % self.port, 'success')