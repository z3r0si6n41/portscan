import socket, math, time, errno
from util import *
from probe import Probe
from payloads import UDPPayloads

class Scanner():
	def __init__(self, target, ports, options):
		self.target = target
		self.ports = ports
		self.options = options
		self.result = dict(tcp=[],udp=[])
		
		if self.options.scan == 'tcp' or self.options.scan == 'both':
			if self.options.verbose:
				Util.msg('Starting TCP scan. Total ports: %d' % (len(ports)), 'info')
			tcpPorts = self.getSegment('tcp', TCP_ASYNC_LIMIT)
			self.result['tcp'] = sorted(tcpPorts)
		
		if self.options.scan == 'udp' or self.options.scan == 'both':
			if self.options.verbose:
				Util.msg('Starting UDP scan. Total ports: %d' % (len(ports)), 'info')
			udpPorts = self.getSegment('udp', UDP_ASYNC_LIMIT)
			self.result['udp'] = sorted(udpPorts)
	
	def getResult(self):
		return self.result
	
	def getSegment(self, scan, limit):
		iterations = int(math.ceil(len(self.ports)/limit))
		openPorts = []
		for i in range(iterations):
			start = i*limit
			stop = (i+1)*limit
			if scan == 'udp':
				result = self.udp(self.ports[start:stop], 8, 0, 8, 0)[0]
			if scan == 'tcp':
				result = self.tcp(self.ports[start:stop])
			if type(result) == tuple:
				openPorts.extend(result[0])
				openPorts.extend(result[1])
			else:
				openPorts.extend(result)
		return openPorts
	
	def iprange(addressrange):
		list=[]
		first3octets = '.'.join(addressrange.split('-')[0].split('.')[:3]) + '.'
		for i in range(int(addressrange.split('-')[0].split('.')[3]),int(addressrange.split('-')[1])+1):
			list.append(first3octets+str(i))
		return list

	def ip2bin(self, ip):
		b = ""
		inQuads = ip.split(".")
		outQuads = 4
		for q in inQuads:
			if q != "":
				b += self.dec2bin(int(q),8)
				outQuads -= 1
		while outQuads > 0:
			b += "00000000"
			outQuads -= 1
		return b

	def dec2bin(self,n,d=None):
		s = ""
		while n>0:
			if n&1:
				s = "1"+s
			else:
				s = "0"+s
			n >>= 1
		if d is not None:
			while len(s)<d:
				s = "0"+s
		if s == "":
			s = "0"
		return s

	def bin2ip(self, b):
		ip = ""
		for i in range(0,len(b),8):
			ip += str(int(b[i:i+8],2))+"."
		return ip[:-1]

	def returnCIDR(c):
		parts = c.split("/")
		baseIP = self.ip2bin(parts[0])
		subnet = int(parts[1])
		ips=[]
		if subnet == 32:
			return self.bin2ip(baseIP)
		else:
			ipPrefix = baseIP[:-(32-subnet)]
			for i in range(2**(32-subnet)):
				ips.append(self.bin2ip(ipPrefix+self.dec2bin(i, (32-subnet))))
			return ips
	
	def udp(self, ports, initialSends=1, retries=UDP_RETRIES, wait=UDP_WAIT, icmpRateLimit=UDP_ICMP_RATE_LIMIT):
		probes = []
		payload = ''
		for port in ports:
			if self.options.verbose:
				Util.msg('Scanning port %d.' % port, 'info')
			probe = Probe(self.target, port, self.options, socket.SOCK_DGRAM)
			probes.append(probe)
			sock = probe.socket
			sock.settimeout(0.5)
			
			for i in range(initialSends):
				if probe.status is not None:
					continue
				try:
					if(str(probe.port) in UDPPayloads):
						payload = UDPPayloads[str(port)]
					else:
						payload = UDPPayloads['zero']
					
					sock.sendto(payload, (probe.target, probe.port))
					d = sock.recv(1024)
					
					if(len(d) > 0):
						probe.receive()
				
				except socket.error as ex:
					if ex.errno == errno.ECONNREFUSED:
						probe.refused()
						break
					else:
						continue
		
		for i in range(retries+1):
			time.sleep(wait)

			for probe in probes:
				if probe.status is not None:
					continue
				sock = probe.socket
				try:
					if(str(probe.port) in UDPPayloads):
						payload = UDPPayloads[str(port)]
					else:
						payload = UDPPayloads['zero']
					
					sock.sendto(payload, (probe.target, probe.port))
					
					d = sock.recv(1024)
					if(len(d) > 0):
						probe.receive()
				except socket.error as ex:
					if ex.errno == errno.ECONNREFUSED:
						probe.refused()
						time.sleep(icmpRateLimit)
					continue

		openPorts = []
		maybePorts = []
		for probe in probes:
			if probe.status is False:
				continue
			elif probe.status:
				Util.msg('udp port %d open' % probe.port, 'success')
				openPorts.append(probe.port)
			else:
				#if self.options.verbose:
					#Util.msg('udp port %d maybe open' % probe.port, 'success')
				maybePorts.append(probe.port)
				probe.socket.close()

		return openPorts, maybePorts
	
	def tcp(self, ports):
		openPorts = []
		probes = []
		filenoMap = {}
		
		poll = select.epoll(len(ports))
		for port in ports:
			if self.options.verbose:
				Util.msg('Scanning port %d.' % port, 'info')
			probe = Probe(self.target, port, self.options)
			sock = probe.socket
			filenoMap[sock.fileno()] = probe
			
			sock.setblocking(0)
			result = sock.connect_ex((probe.target, probe.port))
			
			if result == 0:
				Util.msg('Found open tcp port: %d' % probe.port, 'success')
				openPorts.append(port)
			elif result == errno.EINPROGRESS:
				poll.register(probe.socket, select.EPOLLOUT | select.EPOLLERR | select.EPOLLHUP)
				probes.append(probe)
			else:
				if self.options.verbose:
					Util.msg('tcp connection bad: %s' % result, 'info')
		
		if len(probes) > 0:
			time.sleep(1)
			
			events = poll.poll(TCP_CONNECT_POLLTIME)
			
			for f, flag in events:
				probe = filenoMap[f]
				
				error = probe.socket.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
				
				if not error:
					Util.msg('Found open tcp port: %d' % probe.port, 'success')
					openPorts.append(probe.port)

		for probe in probes:
			probe.socket.close()

		poll.close()

		return openPorts