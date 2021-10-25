#!/usr/bin/env python

import errno, math, random, select, socket, time, sys
from sys import platform
from optparse import OptionParser


TCP_ASYNC_LIMIT = 256
TCP_CONNECT_POLLTIME = 12
UDP_ASYNC_LIMIT = 256
UDP_RETRIES = 8
UDP_WAIT = 1
UDP_ICMP_RATE_LIMIT = 1

W = '\033[1;97m'
Y = '\033[1;93m'
G = '\033[1;92m'
R = '\033[1;91m'
B = '\033[1;94m'
C = '\033[1;96m'
E = '\033[0m'

if 'win' in platform:
	W = Y = G = R = B = C = E = ''

class App():
	def __init__(self):
		App.msg('Port Scanner by z3r0 s!6n41', 'success')
		self.options = self.optionControl()

	def msg(text, type):
		if 'error' in type:
			print(R+'[!] '+E+text)
		if 'warn' in type:
			print(Y+'[!] '+E+text)
		if 'info' in type:
			print(C+'[*] '+E+text)
		if 'success' in type:
			print(G+'[$] '+E+text)
	
	def optionControl(self):
		parser = OptionParser(usage='%prog [options]\r\nexample: python3 %prog -t 127.0.0.1\r\nexample: python3 %prog -t www.example.com')
		parser.add_option('--ports', '-p', dest='ports', action='store', default='basic', help='Ports which to scan. Can be "basic" (1-1024), "all" (1-65536), or a comma-separated list of ports. Defaults to "basic".')
		parser.add_option('--scan', '-s', dest='scan', action='store', default='both', help='Type of scan to run. Can be "udp", "tcp", or "both". Defaults to "both".')
		parser.add_option('--targets', '-t', dest='targets', action='store', help='The targets you would like to scan. Can be a domain, IP address, range of IP addresses, or CIDR range, or a comma-separated (,) list of any of the preceeding.')
		parser.add_option('--verbose', '-v', dest='verbose', action='store_true', default=False, help='Show all program output.')
		
		options, args = parser.parse_args()
		return options
	
	def printResult(self, startTime, results):
		print('\n')
		App.msg('Scan completed in %d seconds.' % (time.time() - startTime), 'info')
		App.msg('-----RESULTS------', 'warn')
		for result in results:
			print('Target: %s (%s) - %s' % (result['target']['target'], result['target']['ip'], result['status']))
			App.msg('TCP ports open:', 'info')
			if len(result['tcp']) > 0:
				for port in result['tcp']:
					App.msg('\t%d' % port, 'success')
			else:
				App.msg('\tNone Found', 'info')
			
			App.msg('UDP ports open:', 'info')
			if len(result['udp']) > 0:
				for port in result['udp']:
					App.msg('\t%d' % port, 'success')
			else:
				App.msg('\tNone Found', 'info')
			print('\n')

class Scanner():
	def __init__(self, target, ports, options):
		self.target = target
		self.ports = ports
		self.options = options
		self.result = dict(tcp=[],udp=[])
		
		if options.scan == 'tcp' or options.scan == 'both':
			if self.options.verbose:
				App.msg('Starting TCP scan. Total ports: %d' % (len(ports)), 'info')
			tcpPorts = self.getSegment('tcp', TCP_ASYNC_LIMIT)
			self.result['tcp'] = sorted(tcpPorts)
		
		if options.scan == 'udp' or options.scan == 'both':
			if options.verbose:
				App.msg('Starting UDP scan. Total ports: %d' % (len(ports)), 'info')
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
		for port in ports:
			probe = Probe(self.target, port, self.options, socket.SOCK_DGRAM)
			probes.append(probe)
			sock = probe.socket
			
			sock.setblocking(0)
			sock.connect((probe.target, probe.port))
			
			for i in range(initialSends):
				if probe.status is not None:
					continue
				try:
					sock.send(b'\x00')
				except socket.error as ex:
					if ex.errno == errno.ECONNREFUSED:
						probe.refused()
						break
					else:
						raise
		
		for i in range(retries+1):
			time.sleep(wait)

			for probe in probes:
				if probe.status is not None:
					continue
				sock = probe.socket
				try:
					sock.send(b'\x01')
				except socket.error as ex:
					if ex.errno == errno.ECONNREFUSED:
						probe.refused()
						time.sleep(icmpRateLimit)
						continue
					else:
						raise

				try:
					sock.recvfrom(8192)
					probe.receive()
					continue
				except socket.error as ex:
					if ex.errno == errno.ECONNREFUSED:
						App.msg('udp recv failed: Error %s: %s' % (errno.errorcode[ex.errno], ex), 'info')
						continue
					elif ex.errno != errno.EAGAIN:
						App.msg('udp recv failed: Error %s: %s' % (errno.errorcode[ex.errno], ex), 'info')
						raise

		openPorts = []
		maybePorts = []
		for probe in probes:
			if probe.status is False:
				continue
			elif probe.status:
				App.msg('udp port %d open' % probe.port, 'success')
				openPorts.append(probe.port)
			else:
				#if self.options.verbose:
					#App.msg('udp port %d maybe open' % probe.port, 'success')
				maybePorts.append(probe.port)
				probe.socket.close()

		return openPorts, maybePorts
	
	def tcp(self, ports):
		openPorts = []
		probes = []
		filenoMap = {}
		
		poll = select.epoll(len(ports))
		for port in ports:
			probe = Probe(self.target, port, self.options)
			sock = probe.socket
			filenoMap[sock.fileno()] = probe
			
			sock.setblocking(0)
			result = sock.connect_ex((probe.target, probe.port))
			
			if result == 0:
				App.msg('Found open tcp port: %d' % probe.port, 'success')
				openPorts.append(port)
			elif result == errno.EINPROGRESS:
				poll.register(probe.socket, select.EPOLLOUT | select.EPOLLERR | select.EPOLLHUP)
				probes.append(probe)
			else:
				if self.options.verbose:
					App.msg('tcp connection bad: %s' % result, 'info')
		
		if len(probes) > 0:
			time.sleep(1)
			
			events = poll.poll(TCP_CONNECT_POLLTIME)
			
			for f, flag in events:
				probe = filenoMap[f]
				
				error = probe.socket.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
				
				if not error:
					App.msg('Found open tcp port: %d' % probe.port, 'success')
					openPorts.append(probe.port)

		for probe in probes:
			probe.socket.close()

		poll.close()

		return openPorts

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
		App.msg('Found udp port: %d' % self.port, 'success')


def main():
	app = App()
	
	if app.options.targets:
		if ',' in app.options.targets:
			app.options.targets = app.options.targets.split(",")
		else:
			app.options.targets = [app.options.targets]
	
	else:
		App.msg('No target specified!', 'error')
	
	allResults = []
	startTime = time.time()
	for target in app.options.targets:
		t = dict(target=target, ip="")
		if '/' in target:
			t['ip'] = Scanner.returnCIDR(target)
		elif '-' in app.options.targets:
			t['ip'] = Scanner.iprange(target)
		else:
			try:
				t['ip'] = socket.gethostbyname(target)
			except: App.msg("Failed to translate hostname to IP address", 'error')
		
		
		result = dict(target=t, status='')
		targetIsValid = False
		try:
			ip = socket.inet_ntoa(socket.inet_aton(t['ip']))
			result['status'] = 'valid'
			targetIsValid = True
		except socket.error:
			try:
				ip = socket.gethostbyname(t['target'])
				result['status'] = 'valid'
				targetIsValid = True
			except socket.gaierror:
				ip = target
				result['status'] = 'invalid'
		
		if targetIsValid:
			ports = []
			if app.options.ports == 'all':
				app.options.ports = '1-65535'
			if app.options.ports == 'basic':
				app.options.ports = '1-1024'
			ranges = (x.split("-") for x in app.options.ports.split(","))
			ports = [i for r in ranges for i in range(int(r[0]), int(r[-1]) + 1)]
			
			random.shuffle(ports)
			
			print("\n")
			App.msg('Preparing to enumerate %s (%s)' % (target, t['ip']), 'info')
			if app.options.verbose == True:
				App.msg('Beginning scan of %d ports on %s' % (len(ports), target), 'info')
			
			try:
				s = Scanner(target, ports, app.options)
				r = s.getResult()
				scanResult = {**r, **result}
				allResults.append(scanResult)
			except KeyboardInterrupt:
				print("\n\n")
				App.msg('Program halted by user', 'error')
				App.msg('Shutting down.', 'error')
				sys.exit(1)
		else:
			App.msg('Invalid host: %s' % target, 'error')
	
	app.printResult(startTime, allResults)
	sys.exit(0)
	
	

main()
