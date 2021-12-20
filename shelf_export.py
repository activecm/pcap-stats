#!/usr/bin/env python3
"""Exports a shelf-created dictionary to stdout.  Tested with DBM files."""

__version__ = '0.0.2'

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



default_shelf_file = os.environ["HOME"] + '/.cache/ip_names'


if __name__ == '__main__':
	import argparse

	parser = argparse.ArgumentParser(description='shelf_export version ' + str(__version__))
	parser.add_argument('-r', '--read', help='Shelf file(s) from which to read dictionary', required=False, default=default_shelf_file)
	(parsed, unparsed) = parser.parse_known_args()
	cl_args = vars(parsed)

	active_shelf = cl_args['read']
	try:
		persistent_dict = shelve.open(active_shelf, flag='r')
	except:
		sys.stderr.write('Unable to open ' + active_shelf + ' for reading, exiting.\n')
		sys.stderr.flush()
		sys.exit(1)

	print('{')
	is_first = True
	for a_key in sorted(persistent_dict):
		if a_key in persistent_dict:
			key_string = force_string(a_key)
			#if "'" in str(persistent_dict[a_key]):
			#	sys.stderr.write('Quote error for ' + str(persistent_dict[a_key]) + '\n')
			#	sys.stderr.flush()
			#else:
			if is_first:
				is_first = False
			else:
				print(',')
			#sys.stdout.write('\t"' + key_string + '": ' + str(persistent_dict[a_key]).replace("'", '"').replace('{', '[').replace('}', ']'))
			sys.stdout.write('\t"' + key_string + '": ' + json.dumps(list(persistent_dict[a_key])))
			sys.stdout.flush()
		else:
			sys.stderr.write('Key error for ' + force_string(a_key) + '\n')
			sys.stderr.flush()

	print('\n}')
