import time
from optparse import OptionParser
from sys import platform

W = '\033[1;97m'
Y = '\033[1;93m'
G = '\033[1;92m'
R = '\033[1;91m'
B = '\033[1;94m'
C = '\033[1;96m'
E = '\033[0m'

if 'win' in platform:
	W = Y = G = R = B = C = E = ''

TCP_ASYNC_LIMIT = 256
TCP_CONNECT_POLLTIME = 12
UDP_ASYNC_LIMIT = 256
UDP_RETRIES = 8
UDP_WAIT = 1
UDP_ICMP_RATE_LIMIT = 1

class Util():
	def __init__(self):
		Util.msg('Port Scanner by z3r0 s!6n41', 'success')
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
		Util.msg('Scan completed in %d seconds.' % (time.time() - startTime), 'info')
		Util.msg('-----RESULTS------', 'warn')
		for result in results:
			print('Target: %s (%s) - %s' % (result['target']['target'], result['target']['ip'], result['status']))
			Util.msg('TCP ports open:', 'info')
			if len(result['tcp']) > 0:
				for port in result['tcp']:
					Util.msg('\t%d' % port, 'success')
			else:
				Util.msg('\tNone Found', 'info')
			
			Util.msg('UDP ports open:', 'info')
			if len(result['udp']) > 0:
				for port in result['udp']:
					Util.msg('\t%d' % port, 'success')
			else:
				Util.msg('\tNone Found', 'info')
			print('\n')