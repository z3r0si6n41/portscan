#!/usr/bin/env python

import sys, re, random, time, math
from sys import platform
import socket
from optparse import OptionParser
from urllib.parse import urlparse

TCP_ASYNC_LIMIT = 256      # number of tcp ports to scan concurrently
TCP_CONNECT_POLLTIME = 12  # seconds poll waits for async tcp connects
UDP_ASYNC_LIMIT = 256      # max udp ports to scan concurrently
UDP_RETRIES = 8            # default number of udp retransmissions
UDP_WAIT = 1               # default wait seconds before retry + receive
UDP_ICMP_RATE_LIMIT = 1    # wait seconds after inferred icmp unreachable

W = '\033[1;97m'
Y = '\033[1;93m'
G = '\033[1;92m'
R = '\033[1;91m'
B = '\033[1;94m'
C = '\033[1;96m'
E = '\033[0m'

if 'win' in platform:
	W = Y = G = R = B = C = E = ''


class Probe():
	def __init__(self, ip, port, options, scanType, _type=socket.SOCK_STREAM):
		self.type = _type
		self.ip = ip
		self.port = port
		self.status = None
		self.options = options
		self.scanType = scanType
		self.socket = socket.socket(socket.AF_INET, _type)
	
	def refused(self):
		self.status = False
		self.socket.close()
		if self.options.verbose == True:
			msg('%d/%s closed' % (self.port, self.scanType), 'warn')
	
	def receive(self):
		self.status = True
		self.socket.close()
		msg('%d/%s open' % (self.port, self.scanType), 'success')



def msg(text, type):
	if 'error' in type:
		print(R+'[!] '+E+text)
	if 'warn' in type:
		print(Y+'[!] '+E+text)
	if 'info' in type:
		print(C+'[*] '+E+text)
	if 'success' in type:
		print(G+'[$] '+E+text)

def is_valid_hostname(hostname):
	if len(hostname) > 255:
		return False
	if hostname[-1] == ".":
		hostname = hostname[:-1]
	allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
	return all(allowed.match(x) for x in hostname.split("."))



def urlParser(target):
	host = ''
	o = urlparse(target)
	if o.scheme not in ['http', 'https', '']:
		msg('Protocol %s not supported' % o.scheme,'error')
		return
	if o.netloc:
		tmp = o.netloc.split(':')
		host = tmp[0]
	else:
		pathPieces = o.path.split('/')
		hostPieces = pathPieces[0].split(':')
		host = hostPieces[0]
	
	if is_valid_hostname(host):
		return host
	else:
		msg('Hostname is malformed. Please check and try again.', 'error')
		return



def optionControl():
	parser = OptionParser(usage='%prog [options]\r\nexample: python3 %prog -t 127.0.0.1\r\nexample: python3 %prog -t www.example.com')
	parser.add_option('--ports', '-p', dest='ports', action='store', default='basic', help='Ports which to scan. Can be "basic" (1-1024), "all" (1-65536), or a comma-separated list of ports. Defaults to "basic".')
	parser.add_option('--scan-type', '-st', dest='type', action='store', default='both', help='Type of scan to run. Can be "udp", "tcp", or "both". Defaults to "both".')
	parser.add_option('--targets', '-t', dest='targets', action='store', help='The targets you would like to scan. Can be a domain, IP address, range of IP addresses, or CIDR range.')
	parser.add_option('--verbose', '-v', dest='verbose', action='store_true',
	default=False, help='Show all program output.')
	
	options, args = parser.parse_args()
	return (options, args)



def scanner(f, ip, ports, limit, options):
	scanType = f.__name__
	if options.verbose == True:
		print("\n\n")
		msg('Performing %s scan.' % scanType, 'info')
	
	iterations = int(math.ceil(len(ports)/limit))
	for i in range(iterations):
		start = i * limit
		stop = (i+1) * limit
		f(ip, ports[start:stop], options)



def tcp(ip, ports, options):
	for port in ports:
		if options.verbose == True:
			msg('Testing port '+str(port)+'/tcp', 'info')
		
		probe = Probe(ip, port, options, 'tcp')
		result = probe.socket.connect_ex((probe.ip, probe.port))
		if result == 0:
			probe.receive()
		else:
			probe.refused()



def udp(ip, ports, options):
	for port in ports:
		if options.verbose == True:
			msg('Testing port '+str(port)+'/udp', 'info')
		
		probe = Probe(ip, port, options, 'udp', socket.SOCK_DGRAM)
		result = probe.socket.connect_ex((probe.ip, probe.port))
		if result == 0:
			probe.receive()
		else:
			probe.refuse()



def iprange(addressrange):
	# converts a ip range into a list
	list=[]
	first3octets = '.'.join(addressrange.split('-')[0].split('.')[:3]) + '.'
	for i in range(int(addressrange.split('-')[0].split('.')[3]),int(addressrange.split('-')[1])+1):
		list.append(first3octets+str(i))
	return list



def ip2bin(ip):
	b = ""
	inQuads = ip.split(".")
	outQuads = 4
	for q in inQuads:
		if q != "":
			b += dec2bin(int(q),8)
			outQuads -= 1
	while outQuads > 0:
		b += "00000000"
		outQuads -= 1
	return b



def dec2bin(n,d=None):
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



def bin2ip(b):
	ip = ""
	for i in range(0,len(b),8):
		ip += str(int(b[i:i+8],2))+"."
	return ip[:-1]



def returnCIDR(c):
	parts = c.split("/")
	baseIP = ip2bin(parts[0])
	subnet = int(parts[1])
	ips=[]
	if subnet == 32:
		return bin2ip(baseIP)
	else:
		ipPrefix = baseIP[:-(32-subnet)]
		for i in range(2**(32-subnet)):
			ips.append(bin2ip(ipPrefix+dec2bin(i, (32-subnet))))
		return ips



def main():
	(options, args) = optionControl()
	print('Portscan by B14ckD347h')
		
	targets = []
	if args.targets:
		if '/' in args.targets:
			targets = returnCIDR(args.targets)
		elif '-' in agrs.targets:
			targets = iprange(args.targets)
		else:
			try:
				targets.append(socket.gethostbyname(args.targets))
				# get IP from FQDN
			except: errormsg("Failed to translate hostname to IP address")
	else:
		msg('No target specified!', 'error')
	
	
	targets = args
	for target in targets:
		msg('Preparing to enumerate %s' % target, 'info')
		
		ports = []
		if options.ports == '-':
			options.ports = '1-65535'
		ranges = (x.split("-") for x in args.ports.split(",")) ports = [i for r in ranges for i in range(int(r[0]), int(r[-1]) + 1)]

		
		
		
		
		
		
		if options.ports:
			if options.ports == 'all':
				ports = list(range(1, 65536))
			elif options.ports == 'basic':
				ports = list(range(1, 1025))
			else:
				for x in options.ports.split(','):
					ports.append(int(x.strip()))
		else:
			ports = range(1, 1025)
		
		startTime = time.time()
		random.shuffle(ports)
		
		if options.verbose == True:
			msg('Beginning scan of %d ports on %s' % (len(ports), target), 'info')
		
		try:
			if options.type == 'both' or options.type == 'tcp':
				scanner(tcp, ip, ports, TCP_ASYNC_LIMIT, options)
			
			if options.type == 'both' or options.type == 'udp':
				scanner(udp, ip, ports, UDP_ASYNC_LIMIT, options)
		except KeyboardInterrupt:
			print("\n\n")
			msg('Program halted by user', 'error')
			msg('Shutting down.', 'error')
			sys.exit(1)
		
		msg('Scan completed in %d seconds.' % (time.time() - startTime), 'info')
		
		exit(0)

if __name__ == '__main__':
	main()
