#!/usr/bin/env python3
"""imports a json dictionary from stdin and merges all items in it to a shelf.  Tested with DBM files."""

__version__ = '0.0.4'

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


def debug_out(output_string):
	"""Send debuging output to stderr."""

	sys.stderr.write(output_string + '\n')
	sys.stderr.flush()


def add_items_to_persistent(item_dict, p_shelf):
	"""Take all the items in the item_dict and add them to p_shelf.  Both are dictionaries."""
	#The stdin dictionary _values_ must all be strings (string will be appended to shelf list if new) or lists (all new list items will be appended to shelf list).

	for one_key in item_dict:
		if item_dict[one_key]:
			if one_key in p_shelf:
				current_list = p_shelf[one_key]
			else:
				current_list = []

			is_modified = False
			if isinstance(item_dict[one_key], str):
				if item_dict[one_key] not in current_list:
					current_list.append(item_dict[one_key])
					is_modified = True
			elif isinstance(item_dict[one_key], list):
				for one_val in item_dict[one_key]:
					if one_val not in current_list:
						current_list.append(one_val)
						is_modified = True
			else:
				debug_out("value associated with " + one_key + " is not a string or list, skipping.")

			if is_modified:
				p_shelf[one_key] = current_list


default_shelf_file = os.environ["HOME"] + '/.cache/ip_names_TEST'		#FIXME before release

if __name__ == '__main__':
	import argparse

	parser = argparse.ArgumentParser(description='shelf_import version ' + str(__version__))
	parser.add_argument('-w', '--write', help='Shelf file to which to write new values (default: %(default)s)', required=False, default=default_shelf_file)
	(parsed, unparsed) = parser.parse_known_args()
	cl_args = vars(parsed)

	active_shelf = cl_args['write']

	stdintext = sys.stdin.buffer.read().decode("utf-8", 'replace')

	try:
		import_items = json.loads(stdintext)
	except json.decoder.JSONDecodeError as e:
		debug_out("Unable to import stdin as a json object, exiting.")
		raise e
	if isinstance(import_items, dict):
		#Here we have a dictionary of items to add to the shelf.

		try:
			persistent_dict = shelve.open(active_shelf, writeback=True)

			add_items_to_persistent(import_items, persistent_dict)
		except:
			debug_out("Cannot open " + active_shelf + " for writing, exiting.")
			sys.exit(1)
	else:
		debug_out("Std input is not a dictionary, exiting.")
		print(import_items)
		print(type(import_items))
		sys.exit(1)

	sys.exit(0)
