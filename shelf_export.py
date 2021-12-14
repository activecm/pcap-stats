#!/usr/bin/env python3

__version__ = '0.0.1'

__author__ = 'William Stearns'
__copyright__ = 'Copyright 2021, William Stearns'
__credits__ = ['William Stearns']
__email__ = 'william.l.stearns@gmail.com'
__license__ = 'GPL 3.0'
__maintainer__ = 'William Stearns'
__status__ = 'Development'                               #Prototype, Development or Production


import os
import sys
import json
import shelve


def force_string(raw_string):
	"""Make sure the returned object is a string."""

	retval = raw_string

	if sys.version_info > (3, 0):		#Python 3
		if isinstance(raw_string, bytes):
			retval = raw_string.decode("utf-8", 'replace')
		elif isinstance(raw_string, str):
			pass
		elif isinstance(raw_string, list):
			retval = ' '.join([force_string(listitem) for listitem in raw_string])
			#print(str(type(raw_string)))
			#print("huh:" + str(raw_string))
			#sys.exit()
		else:
			print(str(type(raw_string)))
			print("huh:" + str(raw_string))
			sys.exit()
			retval = str(raw_string)
	else:
		retval = str(raw_string)

	return retval



ip_names_cache = os.environ["HOME"] + '/.cache/ip_names'

try:
	persistent_hosts_for_ip = shelve.open(ip_names_cache, flag='r')
except:
	sys.stderr.write('Unable to open ip_names cache for reading, exiting.\n')
	sys.stderr.flush()
	persistent_hosts_for_ip = {}
	sys.exit(1)

print('{')
is_first = True
for a_key in sorted(persistent_hosts_for_ip):
	if a_key in persistent_hosts_for_ip:
		key_string = force_string(a_key)
		#if "'" in str(persistent_hosts_for_ip[a_key]):
		#	sys.stderr.write('Quote error for ' + str(persistent_hosts_for_ip[a_key]) + '\n')
		#	sys.stderr.flush()
		#else:
		if is_first:
			is_first = False
		else:
			print(',')
		#sys.stdout.write('\t"' + key_string + '": ' + str(persistent_hosts_for_ip[a_key]).replace("'", '"').replace('{', '[').replace('}', ']'))
		sys.stdout.write('\t"' + key_string + '": ' + json.dumps(list(persistent_hosts_for_ip[a_key])))
		sys.stdout.flush()
	else:
		sys.stderr.write('Key error for ' + force_string(a_key) + '\n')
		sys.stderr.flush()

print('\n}')
