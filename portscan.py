#!/usr/bin/env python

import errno, time, random, select, socket, sys
from util import *
from scanner import Scanner

def main():
	util = Util()
	
	if util.options.targets:
		if ',' in util.options.targets:
			util.options.targets = util.options.targets.split(",")
		else:
			util.options.targets = [util.options.targets]
	
	else:
		Util.msg('No target specified!', 'error')
	
	allResults = []
	startTime = time.time()
	for target in util.options.targets:
		t = dict(target=target, ip="")
		if '/' in target:
			t['ip'] = Scanner.returnCIDR(target)
		elif '-' in util.options.targets:
			t['ip'] = Scanner.iprange(target)
		else:
			try:
				t['ip'] = socket.gethostbyname(target)
			except: Util.msg("Failed to translate hostname to IP address", 'error')
		
		
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
			if util.options.ports == 'all':
				util.options.ports = '1-65535'
			if util.options.ports == 'basic':
				util.options.ports = '1-1024'
			ranges = (x.split("-") for x in util.options.ports.split(","))
			ports = [i for r in ranges for i in range(int(r[0]), int(r[-1]) + 1)]
			
			random.shuffle(ports)
			
			print("\n")
			Util.msg('Preparing to enumerate %s (%s)' % (target, t['ip']), 'info')
			if util.options.verbose == True:
				Util.msg('Beginning scan of %d ports on %s' % (len(ports), target), 'info')
			
			try:
				s = Scanner(target, ports, util.options)
				r = s.getResult()
				scanResult = {**r, **result}
				allResults.append(scanResult)
			except KeyboardInterrupt:
				print("\n\n")
				Util.msg('Program halted by user', 'error')
				Util.msg('Shutting down.', 'error')
				sys.exit(1)
		else:
			Util.msg('Invalid host: %s' % target, 'error')
	
	util.printResult(startTime, allResults)
	sys.exit(0)
	
	

main()