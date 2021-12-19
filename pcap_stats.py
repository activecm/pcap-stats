#!/usr/bin/env python3
"""Print statistics of a pcap file or packets arriving on an interface."""

#Dedicated to the memory of Alan Paller, whose vision of a secure
#Internet gave thousands of us a chance to learn and grow.


__version__ = '0.0.45'

__author__ = 'William Stearns'
__copyright__ = 'Copyright 2021, William Stearns'
__credits__ = ['William Stearns']
__email__ = 'william.l.stearns@gmail.com'
__license__ = 'GPL 3.0'
__maintainer__ = 'William Stearns'
__status__ = 'Production'				#Prototype, Development or Production



import os
import sys
import time
import tempfile
import shelve
import gzip												#Lets us read from gzip-compressed pcap files
import bz2												#Lets us read from bzip2-compressed pcap files
import re												#Regex matching on UUID hostnames

try:
	#from scapy.all import *
	from scapy.all import ARP, DNS, Ether, ICMP, IP, IPv6, LLC, Scapy_Exception, STP, TCP, UDP, sniff				# pylint: disable=no-name-in-module
	from scapy.config import conf
except ImportError:
	sys.stderr.write('Unable to load the scapy library.  Perhaps run   sudo apt install python3-pip || sudo yum install python3-pip ; sudo pip3 install scapy   ?\n')
	sys.stderr.flush()
	sys.exit(1)

try:
	from passer_lib import DNS_extract, explode_ip, generate_meta_from_packet
except ImportError:
	sys.stderr.write('Unable to load the passer_lib library.\n')
	sys.stderr.flush()
	sys.exit(1)


def debug_out(output_string):
	"""Send debuging output to stderr."""

	if cl_args['devel']:
		sys.stderr.write(output_string + '\n')
		sys.stderr.flush()


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


def open_bzip2_file_to_tmp_file(bzip2_filename):
	"""Open up a bzip2 file to a temporary file and return that filename."""

	tmp_fd, tmp_path = tempfile.mkstemp()
	try:
		with os.fdopen(tmp_fd, 'wb') as tmp_h, bz2.BZ2File(bzip2_filename, 'rb') as compressed_file:
			for data in iter(lambda: compressed_file.read(100 * 1024), b''):
				tmp_h.write(data)
		return tmp_path
	except:
		sys.stderr.write("While expanding bzip2 file, unable to write to " + str(tmp_path) + ', exiting.\n')
		raise


def open_gzip_file_to_tmp_file(gzip_filename):
	"""Open up a gzip file to a temporary file and return that filename."""

	tmp_fd, tmp_path = tempfile.mkstemp()
	try:
		with os.fdopen(tmp_fd, 'wb') as tmp_h, gzip.GzipFile(gzip_filename, 'rb') as compressed_file:
			for data in iter(lambda: compressed_file.read(100 * 1024), b''):
				tmp_h.write(data)
		return tmp_path
	except:
		sys.stderr.write("While expanding gzip file, unable to write to " + str(tmp_path) + ', exiting.\n')
		raise


def packet_layers(pkt):
	"""Returns a list of packet layers."""

	layers = []
	counter = 0
	while True:
		layer = pkt.getlayer(counter)
		if layer is not None:
			#print(layer.name)
			layers.append(layer.name)
		else:
			break
		counter += 1

	return layers
	#Sample return	['Ethernet', 'IP', 'TCP']


def packet_len(packet, whichlayer):													# pylint: disable=unused-argument
	"""Finds the appropriate length of the packet based on user preference."""
	#FIXME - only the IP/IPv6 option works at the moment.

	#print(str(len(p)) + " _6_ " + str(p[IPv6].plen))

	if cl_args['length'] == 'ip':
		if packet.haslayer(IP):
			#p[IP].len returns the IP header onwards, but not the ethernet header above it.
			pack_len = packet[IP].len
		elif packet.haslayer(IPv6):
			#p[IPv6].plen returns the IP header onwards, but not the ethernet header above it.
			pack_len = packet[IPv6].plen
		elif packet.haslayer(ARP):
			#p[ARP].len returns the ARP header onwards, but not the ethernet header above it.
			pack_len = packet[ARP].plen
		#FIXME - add else: here to handle other types
	#elif cl_args['length'] == 'layer':
	#	pack_len = 0
	#	if packet.haslayer(IP):
	#		#p[IP].len returns the IP header onwards, but not the ethernet header above it.
	#		pack_len = packet[whichlayer].len
	#	elif packet.haslayer(IPv6):
	#		#p[IPv6].plen returns the IP header onwards, but not the ethernet header above it.
	#		pack_len = packet[whichlayer].plen
	#elif cl_args['length'] == 'payload':
	#	pack_len = 0
	#elif cl_args['length'] == 'ethernet':
	#	pack_len = 0
	#	#len(p) returns the full size of the packet including the ethernet header (and possibly 40 more bytes?)
	else:
		pack_len = 0

	return pack_len


def inc_stats(one_label, length):
	"""Increment the packet count and total size for this layer."""

	if "p_stats" not in inc_stats.__dict__:
		inc_stats.p_stats = {'count': [0, 0]}

	if one_label not in inc_stats.p_stats:
		inc_stats.p_stats[one_label] = [0, 0]
	inc_stats.p_stats[one_label][0] += 1
	inc_stats.p_stats[one_label][1] += length


def processpacket(p):
	"""Extract statistics from a single packet."""

	if "field_filter" not in processpacket.__dict__:
		processpacket.field_filter = {'count': '', 'ARP': 'arp',
		'DHCP6 IA Address Option (IA TA or IA NA suboption)': 'udp port 546 or udp port 547', 'DHCP6 Preference Option': 'udp port 546 or udp port 547', 'DHCP6 Server Identifier Option': 'udp port 546 or udp port 547', 'DHCP6 Status Code Option': 'udp port 546 or udp port 547', 'DHCPv6 Confirm Message': 'udp port 546 or udp port 547', 'DHCPv6 Reply Message': 'udp port 546 or udp port 547',
		'DNS': 'port 53 or udp port 5353 or udp port 5355', 'ESP': 'ip proto esp',
		'ICMPv6 Neighbor Discovery - Neighbor Advertisement': 'icmp6[0] == 136', 'ICMPv6 Neighbor Discovery - Neighbor Solicitation': 'icmp6[0] == 135', 'ICMPv6 Neighbor Discovery - Router Solicitation': 'icmp6[0] == 133', 'IP': 'ip', 'ICMP': 'icmp', 'IPv6': 'ip6', 'ISAKMP': 'port 500 or udp port 4500',
		'NTPHeader': 'udp port 123', 'RIP_entry': 'udp port 520', 'RIP_header': 'udp port 520', 'SNMP': 'port 161 or port 162', 'TCP': 'tcp', 'TFTP_Read_Request': 'port 69', 'TFTP_opcode': 'port 69', 'UDP': 'udp', '802.1Q': 'vlan',
		'TCP_FLAGS_': 'tcp[12:2] & 0x01ff = 0x0000', 'TCP_FLAGS_F': 'tcp[12:2] & 0x01ff = 0x0001', 'TCP_FLAGS_S': 'tcp[12:2] & 0x01ff = 0x0002', 'TCP_FLAGS_R': 'tcp[12:2] & 0x01ff = 0x0004', 'TCP_FLAGS_SR': 'tcp[12:2] & 0x01ff = 0x0006', 'TCP_FLAGS_RP': 'tcp[12:2] & 0x01ff = 0x000C',
		'TCP_FLAGS_A': 'tcp[12:2] & 0x01ff = 0x0010', 'TCP_FLAGS_FA': 'tcp[12:2] & 0x01ff = 0x0011', 'TCP_FLAGS_SA': 'tcp[12:2] & 0x01ff = 0x0012', 'TCP_FLAGS_RA': 'tcp[12:2] & 0x01ff = 0x0014', 'TCP_FLAGS_FRA': 'tcp[12:2] & 0x01ff = 0x0015', 'TCP_FLAGS_PA': 'tcp[12:2] & 0x01ff = 0x0018', 'TCP_FLAGS_FPA': 'tcp[12:2] & 0x01ff = 0x0019', 'TCP_FLAGS_RPA': 'tcp[12:2] & 0x01ff = 0x001C',
		'TCP_FLAGS_U': 'tcp[12:2] & 0x01ff = 0x0020', 'TCP_FLAGS_SU': 'tcp[12:2] & 0x01ff = 0x0022', 'TCP_FLAGS_FPU': 'tcp[12:2] & 0x01ff = 0x0029', 'TCP_FLAGS_FSPU': 'tcp[12:2] & 0x01ff = 0x002b',
		'TCP_FLAGS_SAU': 'tcp[12:2] & 0x01ff = 0x0032', 'TCP_FLAGS_FSRPAU': 'tcp[12:2] & 0x01ff = 0x003f',
		'TCP_FLAGS_AE': 'tcp[12:2] & 0x01ff = 0x0050', 'TCP_FLAGS_FAE': 'tcp[12:2] & 0x01ff = 0x0051', 'TCP_FLAGS_SAE': 'tcp[12:2] & 0x01ff = 0x0052',
		'TCP_FLAGS_AC': 'tcp[12:2] & 0x01ff = 0x0090', 'TCP_FLAGS_RAC': 'tcp[12:2] & 0x01ff = 0x0094', 'TCP_FLAGS_SPAC': 'tcp[12:2] & 0x01ff = 0x0095', 'TCP_FLAGS_PAC': 'tcp[12:2] & 0x01ff = 0x0098',
		'TCP_FLAGS_SEC': 'tcp[12:2] & 0x01ff = 0x00c2', 'TCP_FLAGS_FSPEC': 'tcp[12:2] & 0x01ff = 0x00cb',
		'TCP_FLAGS_SAEC': 'tcp[12:2] & 0x01ff = 0x00d2',
		'TCP_FLAGS_AN': 'tcp[12:2] & 0x01ff = 0x0110', 'TCP_FLAGS_FAN': 'tcp[12:2] & 0x01ff = 0x0111', 'TCP_FLAGS_RAN': 'tcp[12:2] & 0x01ff = 0x0114',
		'TCP_FLAGS_FSRPAUEN': 'tcp[12:2] & 0x01ff = 0x017f'}

		#Scapy flags
		#N	NS		0x0100	(ECN Nonce - concealment protection.  See https://en.wikipedia.org/wiki/Transmission_Control_Protocol)
		#C	CWR		  0x80
		#E	ECN		  0x40
		#U	URG		  0x20
		#A	ACK		  0x10
		#P	PSH		  0x08
		#R	RST		  0x04
		#S	SYN		  0x02
		#F	FIN		  0x01

	if "tcp_server_ports" not in processpacket.__dict__:
		processpacket.tcp_server_ports = [7, 13, 21, 22, 23, 25, 53, 79, 80, 88, 110, 111, 113, 135, 139, 143, 389, 443, 445, 514, 631, 902, 990, 993, 995, 1433, 1521, 1723, 2222, 3128, 3306, 3389, 5000, 5001, 5060, 5223, 5228, 5432, 5601, 5900, 7070, 7680, 8008, 8009, 8080, 8088, 8333, 8443, 9200, 9443, 49152]

	if "udp_server_ports" not in processpacket.__dict__:
		processpacket.udp_server_ports = [7, 53, 67, 123, 137, 138, 192, 443, 1900, 2190, 5002, 5353, 5355, 8200, 16384, 16385, 16386, 17500, 19305, 56833, 60682, 62988]

	if "local_ips" not in processpacket.__dict__:
		processpacket.local_ips = set([])

	if "minstamp" not in processpacket.__dict__:
		processpacket.minstamp = None
	if "maxstamp" not in processpacket.__dict__:
		processpacket.maxstamp = None

	if "ipv4s_for_mac" not in processpacket.__dict__:
		processpacket.ipv4s_for_mac = {}
	if "ipv6s_for_mac" not in processpacket.__dict__:
		processpacket.ipv6s_for_mac = {}

	if 'hosts_for_ip' not in processpacket.__dict__:		#Dictionary; keys are IP addresses, values are sets of hostnames
		processpacket.hosts_for_ip = {}
		#FIXME - add netbios names too?

	if 'ports_for_ip' not in processpacket.__dict__:		#Dictionary; keys are IP addresses, values are sets of ports used by this IP (specifically, the ports at the IP's end of the connection)
		processpacket.ports_for_ip = {}

	if 'cast_type' not in processpacket.__dict__:			#Dictionary; keys are IP addresses, values are one of 'broadcast', 'multicast', (or unicast, though we don't remember this as it's the default.)
		processpacket.cast_type = {}

	p_layers = packet_layers(p)

	prefs = {'nxdomain': False, 'devel': cl_args['devel'], 'quit': False}
	dests = {'unhandled': None}
	meta = generate_meta_from_packet(p, prefs, dests)

	if p.haslayer(IP):
		i_layer = p.getlayer(IP)
		p_len = packet_len(p, IP)
		proto = str(i_layer.proto)
		ttl = int(i_layer.ttl)
		sIP = i_layer.src
		dIP = i_layer.dst
		label = 'ip4_' + sIP
		inc_stats(label, p_len)
		processpacket.field_filter[label] = 'host ' + sIP
		label = 'ip4_' + dIP
		inc_stats(label, p_len)
		processpacket.field_filter[label] = 'host ' + dIP
	elif p.haslayer(IPv6):
		i_layer = p.getlayer(IPv6)
		p_len = packet_len(p, IPv6)
		proto = str(i_layer.nh)
		ttl = int(i_layer.hlim)
		sIP = i_layer.src
		dIP = i_layer.dst
		label = 'ip6_' + sIP
		inc_stats(label, p_len)
		processpacket.field_filter[label] = 'ip6 host ' + sIP
		label = 'ip6_' + dIP
		inc_stats(label, p_len)
		processpacket.field_filter[label] = 'ip6 host ' + dIP
	elif p.haslayer(ARP):
		i_layer = None
		p_len = packet_len(p, ARP)
		proto = None
		ttl = -1
		sIP = p.getlayer(ARP).psrc
		dIP = p.getlayer(ARP).pdst
	elif (p.haslayer(Ether) and p[Ether].type == 0x888E):				#EAPOL packet; PAE=0x888E
		i_layer = None
		p_len = 0		#FIXME
		proto = None
		ttl = -1
		sIP = None
		dIP = None
	elif p.haslayer(LLC) or p.haslayer(STP):
		i_layer = None
		p_len = 0		#FIXME
		proto = None
		ttl = -1
		sIP = None
		dIP = None
	elif p_layers == ['Ethernet', 'Raw']:
		i_layer = None
		p_len = 0		#FIXME
		proto = None
		ttl = -1
		sIP = None
		dIP = None
	else:
		print("Ethernet type")
		print(p[Ether].type)
		p.show()
		sys.exit(99)
		i_layer = None
		p_len = 0		#FIXME
		proto = None
		ttl = -1
		sIP = None
		dIP = None

	inc_stats('count', p_len)

	if sIP and sIP not in ('0.0.0.0', '::') and not sIP.startswith(('169.254.', 'fe80:')) and p.haslayer(Ether):	#We remember all the IPv4 and IPv6 addresses associated with a particular mac to decide later whether a mac address is a router.
		sMAC = p.getlayer(Ether).src
		if ':' in sIP:
			if sMAC not in processpacket.ipv6s_for_mac:
				processpacket.ipv6s_for_mac[sMAC] = set([])
			processpacket.ipv6s_for_mac[sMAC].add(sIP)
		else:
			if sMAC not in processpacket.ipv4s_for_mac:
				processpacket.ipv4s_for_mac[sMAC] = set([])
			processpacket.ipv4s_for_mac[sMAC].add(sIP)

	for a_layer in p_layers:
		if a_layer not in ignore_layers:
			inc_stats(a_layer, p_len)

	if p.haslayer(Ether):
		if p[Ether].dst == 'ff:ff:ff:ff:ff:ff':
			label = 'ethernet_broadcast'
			inc_stats(label, p_len)
			processpacket.field_filter[label] = 'ether broadcast'
			if dIP and (p.haslayer(IPv6) or p.haslayer(IP)):
				processpacket.cast_type[dIP] = 'broadcast'
		elif p[Ether].dst.startswith(('01:00:5e:', '33:33:', '01:80:c2:')):
			label = 'ethernet_multicast'
			inc_stats(label, p_len)
			processpacket.field_filter[label] = 'ether multicast'
			if dIP and (p.haslayer(IPv6) or p.haslayer(IP)):
				processpacket.cast_type[dIP] = 'multicast'
		else:
			label = 'ethernet_unicast'
			inc_stats(label, p_len)
			processpacket.field_filter[label] = 'not (ether broadcast) and not (ether multicast)'
	else:
		label = 'non_ethernet'
		inc_stats(label, p_len)
		#processpacket.field_filter[label] = '...'	#unsure


	if p.haslayer(DNS) and (isinstance(p[DNS], DNS)):
		dns_tuples = DNS_extract(p, meta, prefs, dests)
		#print(str(dns_tuples))

		for one_tuple in dns_tuples:
			if one_tuple[0] == 'DN':
				if one_tuple[2] in ('A', 'AAAA', 'PTR', 'CNAME'):
					if one_tuple[1] and one_tuple[3]:				#Check that the IP and hostname fields are not empty
						ip_string = force_string(one_tuple[1])
						if ip_string not in processpacket.hosts_for_ip:
							processpacket.hosts_for_ip[ip_string] = set()
						processpacket.hosts_for_ip[ip_string].add(force_string(one_tuple[3]))
				#else:
				#	print(str(one_tuple))
			elif one_tuple[0] in ('US', 'UC', 'TS', 'IP'):
				pass
			else:
				debug_out(str(one_tuple))

	if sIP != '::':
		if ttl == 255:										#The system is sending a broadcast - it must be local
			processpacket.local_ips.add(sIP)
		elif ttl in (64, 128):									#The ttl appears to be what it would be set to if it was on the local network.  Flag as a local IP.
			processpacket.local_ips.add(sIP)
		elif ttl == 1 and p.haslayer(UDP) and p.getlayer(UDP).dport in (5353, 5355):		#The ttl appears to be what it would be set to if it was on the local network.  Flag as a local IP.
			processpacket.local_ips.add(sIP)

	if p.haslayer(ARP):
		if p.getlayer(ARP).op == 1:								#1 is a request ("who-has")
			processpacket.local_ips.add(sIP)
			#Note, the destination IP is likely "broadcast" in a request
		elif p.getlayer(ARP).op == 2:								#2 is a reply ("is-at")
			processpacket.local_ips.add(sIP)
			processpacket.local_ips.add(dIP)
		else:
			p.show()
			sys.exit(98)

	#Good for debugging
	#if sIP and ttl != -1:
	#	label = 'ipttl_' + sIP + '_' + str(ttl)
	#	inc_stats(label, p_len)
	#	if ':' in sIP:
	#		processpacket.field_filter[label] = 'src host ' + sIP + ' and ip6[7] = ' + str(ttl)
	#	else:
	#		processpacket.field_filter[label] = 'src host ' + sIP + ' and ip[8] = ' + str(ttl)

	p_epoch = p.time				#Seconds and microseconds since the epoch of this packet
	if processpacket.minstamp is None or p_epoch < processpacket.minstamp:
		processpacket.minstamp = p_epoch

	if processpacket.maxstamp is None or p_epoch > processpacket.maxstamp:
		processpacket.maxstamp = p_epoch

	#Details: https://stackoverflow.com/questions/46276152/scapy-timestamp-measurement-for-outgoing-packets
	#p_gmt = time.gmtime(p_epoch)			#Same timestamp, but in struct_time format for GMT
	#print(p_gmt)					#time.struct_time(tm_year=2021, tm_mon=7, tm_mday=20, tm_hour=21, tm_min=41, tm_sec=3, tm_wday=1, tm_yday=201, tm_isdst=0)
	#print(time.asctime(p_gmt))			#Tue Jul 20 21:41:03 2021



	if p.haslayer(TCP):
		t_layer = p.getlayer(TCP)
		#p.show()
		#sys.exit(97)


		if t_layer.flags == 'S' and t_layer.dport not in processpacket.tcp_server_ports:	#Following blocks try to identify which end is the "server" port.
			debug_out("Adding " + str(t_layer.dport) + " to tcp_server_ports")
			processpacket.tcp_server_ports.append(t_layer.dport)
		elif t_layer.flags == 'SA' and t_layer.sport not in processpacket.tcp_server_ports:
			debug_out("Adding " + str(t_layer.sport) + " to tcp_server_ports")
			processpacket.tcp_server_ports.append(t_layer.sport)

		if t_layer.sport in processpacket.tcp_server_ports:
			label = 'tcp_' + str(t_layer.sport)
			inc_stats(label, p_len)
			processpacket.field_filter[label] = 'tcp port ' + str(t_layer.sport)
		elif t_layer.dport in processpacket.tcp_server_ports:
			label = 'tcp_' + str(t_layer.dport)
			inc_stats(label, p_len)
			processpacket.field_filter[label] = 'tcp port ' + str(t_layer.dport)
		#elif t_layer.sport in tcp_ignore_ports and t_layer.dport in tcp_ignore_ports:		#Was used for early troubleshooting, no longer needed.
		#	pass
		else:
			debug_out("No tcp server port: " + str(t_layer.sport) + " " + str(t_layer.dport))
			#p.show()
			#sys.exit(96)

		if sIP and sIP != '0.0.0.0':
			if sIP not in processpacket.ports_for_ip:
				processpacket.ports_for_ip[sIP] = set()
			processpacket.ports_for_ip[sIP].add('tcp_' + str(t_layer.sport))

		if dIP and dIP != '0.0.0.0':
			if dIP not in processpacket.ports_for_ip:
				processpacket.ports_for_ip[dIP] = set()
			processpacket.ports_for_ip[dIP].add('tcp_' + str(t_layer.dport))

		label = 'TCP_FLAGS_' + str(t_layer.flags)
		inc_stats(label, p_len)

	elif p.haslayer(UDP):
		u_layer = p.getlayer(UDP)
		if u_layer.sport in processpacket.udp_server_ports:					#Following blocks try to identify which end is the "server" port.
			label = 'udp_' + str(u_layer.sport)
			inc_stats(label, p_len)
			processpacket.field_filter[label] = 'udp port ' + str(u_layer.sport)
		elif u_layer.dport in processpacket.udp_server_ports:
			label = 'udp_' + str(u_layer.dport)
			inc_stats(label, p_len)
			processpacket.field_filter[label] = 'udp port ' + str(u_layer.dport)
		elif u_layer.sport >= 33434 and u_layer.sport < 33524:					#Special case traceroute if we didn't find it in the fixed ports above
			label = 'udp_' + str(u_layer.sport)
			inc_stats(label, p_len)
			processpacket.field_filter[label] = 'udp port ' + str(u_layer.sport)
		elif u_layer.dport >= 33434 and u_layer.dport < 33524:
			label = 'udp_' + str(u_layer.dport)
			inc_stats(label, p_len)
			processpacket.field_filter[label] = 'udp port ' + str(u_layer.dport)
		#elif u_layer.sport in udp_ignore_ports and u_layer.dport in udp_ignore_ports:		#Was used for early troubleshooting, no longer needed.
		#	pass
		else:
			label = 'udp_' + str(u_layer.sport)
			inc_stats(label, p_len)
			processpacket.field_filter[label] = 'udp port ' + str(u_layer.sport)
			label = 'udp_' + str(u_layer.dport)
			inc_stats(label, p_len)
			processpacket.field_filter[label] = 'udp port ' + str(u_layer.dport)

			#debug_out("No udp server port")
			#p.show()
			#sys.exit(95)

		if sIP and sIP != '0.0.0.0':
			if sIP not in processpacket.ports_for_ip:
				processpacket.ports_for_ip[sIP] = set()
			processpacket.ports_for_ip[sIP].add('udp_' + str(u_layer.sport))

		if dIP and dIP != '0.0.0.0':
			if dIP not in processpacket.ports_for_ip:
				processpacket.ports_for_ip[dIP] = set()
			processpacket.ports_for_ip[dIP].add('udp_' + str(u_layer.dport))

	elif p.haslayer(ICMP):
		i_layer = p.getlayer(ICMP)
		label = 'icmp_' + str(i_layer.type) + '.' + str(i_layer.code)
		inc_stats(label, p_len)
		processpacket.field_filter[label] = 'icmptype = ' + str(i_layer.type) + ' and icmpcode = ' + str(i_layer.code)
		#p.show()
		#sys.exit(94)
	#IPv6 doesn't have a dedicated ICMPv6 layer, so we need to key off the IPv6 next_header value of 58 for ICMPv6
	elif p.haslayer(IPv6) and p.getlayer(IPv6).nh == 58:
		i_layer = p.getlayer('IPv6').payload
		label = 'icmp6_' + str(i_layer.type) + '.' + str(i_layer.code)
		inc_stats(label, p_len)
		#processpacket.field_filter[label] = 'icmptype = ' + str(i_layer.type) + ' and icmpcode = ' + str(i_layer.code)		#I don't believe this works on ipv6

		#If we want to get down into the individual icmp types:
		#debug_out(label)
		#if i_layer.type == 1:					#'ICMPv6 Destination Unreachable'
		#	debug_out('dest_unreach')
		#elif i_layer.type == 3:					#'ICMPv6 Time Exceeded'
		#	debug_out('time exceeded')
		#elif i_layer.type == 134:				#'ICMPv6 Neighbor Discovery - Router Advertisement'
		#	debug_out('router_adv')
		#elif i_layer.type == 135:				#'ICMPv6 Neighbor Discovery - Neighbor Solicitation'
		#	debug_out('neighbor_sol')
		#elif i_layer.type == 136:				#'ICMPv6 Neighbor Discovery - Neighbor Advertisement'
		#	debug_out('neighbor_adv')
		#else:
		#	p.show()
		#	debug_out(p_layers)
		#	sys.exit(93)
	elif p.haslayer(ARP) or p.haslayer(LLC):
		pass
	elif proto:
		label = 'proto_' + str(proto)
		inc_stats(label, p_len)
		processpacket.field_filter[label] = 'ip proto ' + str(proto)

	elif p.haslayer(IPv6):						#use "ip6 proto"
		pass							#FIXME
	elif p_layers == ['Ethernet', 'Raw']:
		pass
	elif (p.haslayer(Ether) and p[Ether].type == 0x888E):				#EAPOL packet; PAE=0x888E
		pass
	else:
		debug_out("Non-udp-tcp")
		p.show()
		sys.exit(92)


def hints_for(proto_desc, single_port, local_info, cast_info, name_list):
	"""For a given protocol, return the appropriate hint information to go in field 5 of the output."""

	hint_return = ''

	if proto_desc in hints:
		hint_return = hints[proto_desc]
	elif proto_desc.startswith(('ip4_169.254.',)):
		hint_return = 'link_local/unable_to_get_address'
	elif proto_desc.startswith(('ip6_fe80:')):
		hint_return = 'link_local_address'
	elif proto_desc.startswith(('ip4_10.', 'ip4_172.16.', 'ip4_172.17.', 'ip4_172.18.', 'ip4_172.19.', 'ip4_172.20.', 'ip4_172.21.', 'ip4_172.22.', 'ip4_172.23.', 'ip4_172.24.', 'ip4_172.25.', 'ip4_172.26.', 'ip4_172.27.', 'ip4_172.28.', 'ip4_172.29.', 'ip4_172.30.', 'ip4_172.31.', 'ip4_192.168.')):
		hint_return = 'rfc1918/reserved'
	elif proto_desc.startswith(('ip4_17.')):
		hint_return = 'apple'
	elif proto_desc.startswith(('ip4_73.')):
		hint_return = 'comcast'
	else:
		hint_return = ''

	if hint_return and single_port:
		hint_return += ' ' + single_port
	elif single_port:
		hint_return = single_port

	if hint_return and local_info:
		hint_return += ' ' + local_info
	elif local_info:
		hint_return = local_info

	if hint_return and cast_info:
		hint_return += ' ' + cast_info
	elif cast_info:
		hint_return = cast_info

	if hint_return and name_list and name_list != '[]':
		hint_return += ' ' + name_list
	elif name_list and name_list != '[]':
		hint_return = name_list


	return hint_return


def print_stats(mincount_to_show, minsize_to_show, out_format, source_string):
	"""Show statistics"""

	if "p_stats" in inc_stats.__dict__:

		hostcache_state = ''
		hostcache_updates_needed = []
		try:
			persistent_hosts_for_ip = shelve.open(ip_names_cache, flag='r')
			hostcache_state = 'readonly'
		except:
			debug_out('Unable to open ip_names cache for reading')
			persistent_hosts_for_ip = {}

		if out_format == 'html':
			print('<html>')
			print('<head>')
			print('<title>pcap_stats for ' + source_string + '</title>')
			print('</head>')
			print('<body>')
			print('<table border=1>')
			print('<tr><th colspan=6 bgcolor="#ffffff">Pcap Statistics for ' + source_string + '</th></tr>')
			print("<tr><th colspan=5>Begin_time: " + time.asctime(time.gmtime(int(processpacket.minstamp))) + ", End_time: " + time.asctime(time.gmtime(int(processpacket.maxstamp))) + ", Elapsed_time: " + str(processpacket.maxstamp - processpacket.minstamp) + " seconds</th></tr>")
			print('<tr><th>Count</th><th>Bytes</th><th>Description</th><th>BPF expression</th><th>Hint</th></tr>')

			#print(inc_stats.p_stats)
			#print("Local_IPs: " + str(sorted(processpacket.local_ips)))

		elif out_format == 'ascii':
			print("Begin_time: " + time.asctime(time.gmtime(int(processpacket.minstamp))))
			print("End_time: " + time.asctime(time.gmtime(int(processpacket.maxstamp))))
			print("Elapsed_time: " + str(processpacket.maxstamp - processpacket.minstamp))

		for one_key in sorted(inc_stats.p_stats.keys()):
			desc = one_key.replace(' ', '_')
			orig_ip = desc.replace('ip4_', '').replace('ip6_', '')
			full_ip = explode_ip(orig_ip, {}, {})
			if full_ip in processpacket.hosts_for_ip and full_ip in persistent_hosts_for_ip:
				if display_uuid_hosts:
					orig_ip_list = processpacket.hosts_for_ip[full_ip].union(persistent_hosts_for_ip[full_ip])
				else:
					orig_ip_list = [x for x in processpacket.hosts_for_ip[full_ip].union(persistent_hosts_for_ip[full_ip]) if not re.match(uuid_match, x)]
				orig_ip_names = str(orig_ip_list)
				if not processpacket.hosts_for_ip[full_ip].issubset(persistent_hosts_for_ip[full_ip]):
					hostcache_updates_needed.append(full_ip)
			elif full_ip in processpacket.hosts_for_ip:
				if display_uuid_hosts:
					orig_ip_list = processpacket.hosts_for_ip[full_ip]
				else:
					orig_ip_list = [x for x in processpacket.hosts_for_ip[full_ip] if not re.match(uuid_match, x)]
				orig_ip_names = str(orig_ip_list)
				hostcache_updates_needed.append(full_ip)
			elif full_ip in persistent_hosts_for_ip:
				if display_uuid_hosts:
					orig_ip_list = persistent_hosts_for_ip[full_ip]
				else:
					orig_ip_list = [x for x in persistent_hosts_for_ip[full_ip] if not re.match(uuid_match, x)]
				orig_ip_names = str(orig_ip_list)
			else:
				orig_ip_names = ''

			if desc.startswith(('ip4_', 'ip6_')) and orig_ip in processpacket.ports_for_ip:
				if len(processpacket.ports_for_ip[orig_ip]) == 1:
					for sole_port in processpacket.ports_for_ip[orig_ip]:
						break								#Just retrieve the sole entry in the set
					sole_port = 'sole port: ' + str(sole_port)				# pylint: disable=undefined-loop-variable
				elif len(processpacket.ports_for_ip[orig_ip]) == 2 and 'udp_53' in processpacket.ports_for_ip[orig_ip] and 'tcp_53' in processpacket.ports_for_ip[orig_ip]:
					sole_port = 'udp_53_and_tcp_53'
				else:
					sole_port = str(len(processpacket.ports_for_ip[orig_ip])) + ' ports'
			else:
				sole_port = ''

			if desc.startswith(('ip4_', 'ip6_')) and orig_ip in processpacket.cast_type:
				cast_string = processpacket.cast_type[orig_ip]
			else:
				cast_string = ''

			if inc_stats.p_stats[one_key][0] >= mincount_to_show and inc_stats.p_stats[one_key][1] >= minsize_to_show:
				is_local = ''
				if orig_ip in processpacket.local_ips:
					is_local = 'local'

					for one_mac in processpacket.ipv4s_for_mac.keys():
						if orig_ip in processpacket.ipv4s_for_mac[one_mac] and len(processpacket.ipv4s_for_mac[one_mac]) > 10:
							is_local += ' ipv4router ' + str(list(processpacket.ipv4s_for_mac[one_mac])[0:10]) + '..., ' + str(len(processpacket.ipv4s_for_mac[one_mac])) + ' entries.'
						elif orig_ip in processpacket.ipv4s_for_mac[one_mac] and len(processpacket.ipv4s_for_mac[one_mac]) > 1:
							is_local += ' ipv4router ' + str(processpacket.ipv4s_for_mac[one_mac])
					for one_mac in processpacket.ipv6s_for_mac.keys():
						if orig_ip in processpacket.ipv6s_for_mac[one_mac] and len(processpacket.ipv6s_for_mac[one_mac]) > 10:
							is_local += ' ipv6router ' + str(list(processpacket.ipv6s_for_mac[one_mac])[0:10]) + '..., ' + str(len(processpacket.ipv6s_for_mac[one_mac])) + ' entries.'
						elif orig_ip in processpacket.ipv6s_for_mac[one_mac] and len(processpacket.ipv6s_for_mac[one_mac]) > 1:
							is_local += ' ipv6router ' + str(processpacket.ipv6s_for_mac[one_mac])

				try:
					if out_format == 'html':
						print("<tr><td align=right>{0:}</td><td align=right>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td></tr>".format(inc_stats.p_stats[one_key][0], inc_stats.p_stats[one_key][1], desc, processpacket.field_filter.get(one_key, ''), hints_for(desc, sole_port, is_local, cast_string, orig_ip_names)))
					elif out_format == 'ascii':
						print("{0:>10d} {1:>13d} {2:60s} {3:48s} {4:30s}".format(inc_stats.p_stats[one_key][0], inc_stats.p_stats[one_key][1], desc, processpacket.field_filter.get(one_key, ''), hints_for(desc, sole_port, is_local, cast_string, orig_ip_names)))
				except BrokenPipeError:
					sys.exit(0)
		if out_format == 'html':
			print('</table>')
			print('</body></html>')


		if hostcache_state:
			persistent_hosts_for_ip.close()

		if hostcache_updates_needed:
			try:
				persistent_hosts_for_ip = shelve.open(ip_names_cache, writeback=True)
				hostcache_state = 'readwrite'

				for full_ip in hostcache_updates_needed:
					if full_ip in persistent_hosts_for_ip:
						new_hostlist = processpacket.hosts_for_ip[full_ip].union(persistent_hosts_for_ip[full_ip])
					else:
						new_hostlist = processpacket.hosts_for_ip[full_ip]
					debug_out(str(full_ip) + ': ' + str(new_hostlist))
					persistent_hosts_for_ip[full_ip] = new_hostlist

				persistent_hosts_for_ip.close()
			except:
				debug_out('Unable to open ip_names cache for writing')
	else:
		sys.stderr.write('It does not appear any packets were read.  Exiting.\n')
		sys.stderr.flush()


def process_packet_source(if_name, pcap_source, user_args):
	"""Process the packets in a single source file, interface, or stdin."""

	source_file = None
	close_temp = False
	delete_temp = False

	#We have an interface to sniff on
	if if_name:
		debug_out('Reading packets from interface ' + if_name)
		try:
			if user_args['count']:
				sniff(store=0, iface=if_name, filter=user_args['bpf'], count=user_args['count'], prn=lambda x: processpacket(x))	# pylint: disable=unnecessary-lambda
			else:
				sniff(store=0, iface=if_name, filter=user_args['bpf'], prn=lambda x: processpacket(x))					# pylint: disable=unnecessary-lambda
		except Scapy_Exception:
			sys.stderr.write("Unable to open interface " + str(pcap_source) + ' .  Permission error?  Perhaps runs as root or under sudo?  Exiting.\n')
			raise
	#Read from stdin
	elif pcap_source in ('-', None):
		debug_out('Reading packets from stdin.')
		tmp_packets = tempfile.NamedTemporaryFile(delete=True)											# pylint: disable=consider-using-with
		tmp_packets.write(sys.stdin.buffer.read())
		tmp_packets.flush()
		source_file = tmp_packets.name
		close_temp = True
	#Set up source packet file; next 2 sections check for and handle compressed file extensions first, then final "else" treats the source as a pcap file
	elif pcap_source.endswith('.bz2'):
		debug_out('Reading bzip2 compressed packets from file ' + pcap_source)
		source_file = open_bzip2_file_to_tmp_file(pcap_source)
		delete_temp = True
	elif pcap_source.endswith('.gz'):
		debug_out('Reading gzip compressed packets from file ' + pcap_source)
		source_file = open_gzip_file_to_tmp_file(pcap_source)
		delete_temp = True
	else:
		debug_out('Reading packets from file ' + pcap_source)
		source_file = pcap_source

	#Try to process file first
	if source_file:
		try:
			if user_args['count']:
				sniff(store=0, offline=source_file, filter=user_args['bpf'], count=user_args['count'], prn=lambda x: processpacket(x))	# pylint: disable=unnecessary-lambda
			else:
				sniff(store=0, offline=source_file, filter=user_args['bpf'], prn=lambda x: processpacket(x))				# pylint: disable=unnecessary-lambda
		except (FileNotFoundError, IOError):
			sys.stderr.write("Unable to open file " + str(pcap_source) + ', exiting.\n')
			raise

	if close_temp:
		tmp_packets.close()

	if delete_temp and source_file != pcap_source and os.path.exists(source_file):
		os.remove(source_file)



display_uuid_hosts = False
uuid_match = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.local\.'

hints = {'TCP_FLAGS_': 'Invalid/no_tcp_flags', 'TCP_FLAGS_SR': 'Invalid/syn_and_rst', 'TCP_FLAGS_FRA': 'Invalid/fin_and_rst', 'TCP_FLAGS_FSPEC': 'Invalid/fin_and_syn', 'TCP_FLAGS_FSPU': 'Invalid/fin_and_syn', 'TCP_FLAGS_FSRPAU': 'Invalid/fin_and_syn_and_rst', 'TCP_FLAGS_FSRPAUEN': 'Invalid/fin_and_syn_and_rst_christmas_tree',
         'icmp_0.0': 'echo_reply',
         'icmp_3.0': 'unreachable/net', 'icmp_3.1': 'unreachable/host', 'icmp_3.10': 'unreachable/host_admin_prohib', 'icmp_3.13': 'unreachable/communication_administratively_prohibited', 'icmp_3.2': 'unreachable/protocol', 'icmp_3.3': 'unreachable/port', 'icmp_3.4': 'unreachable/frag_needed_and_df_set',
         'icmp_5.0': 'redirect/net', 'icmp_5.1': 'redirect/host', 'icmp_5.2': 'redirect/tos_and_net', 'icmp_5.3': 'redirect/tos_and_host',
         'icmp_8.0': 'echo_request',
         'icmp_9.0': 'router_advertisement/normal',
         'icmp_11.0': 'time_exceeded/TTL', 'icmp_11.1': 'time_exceeded/frag_reassembly_time_exceeded',
         'icmp_13.0': 'timestamp',
         'icmp_14.0': 'timestamp_reply',
         'icmp6_1.1': 'unreachable/communication_administratively_prohibited', 'icmp6_1.3': 'unreachable/address_unreachable', 'icmp6_1.4': 'unreachable/port_unreachable', 'icmp6_1.6': 'unreachable/reject_destination_route',
         'icmp6_3.0': 'time_exceeded/hop_limit',
         'icmp6_128.0': 'echo_request',
         'icmp6_129.0': 'echo_reply',
         'icmp6_133.0': 'router_solicitation/normal',
         'icmp6_134.0': 'router_advertisement/normal',
         'icmp6_135.0': 'neighbor_solicitation/normal',
         'icmp6_136.0': 'neighbor_advertisement/normal',
         'ip4_0.0.0.0': 'address_unspecified', 'ip4_1.1.1.1': 'public_dns/cloudflare', 'ip4_127.0.0.1': 'localhost', 'ip4_8.8.4.4': 'public_dns/google', 'ip4_8.8.8.8': 'public_dns/google', 'ip4_75.75.75.75': 'public_dns/cdns01.comcast.net', 'ip4_75.75.76.76': 'public_dns/cdns02.comcast.net', 'ip4_75.75.77.22': 'public_dns/doh.xfinity.com', 'ip4_75.75.77.98': 'public_dns/doh.xfinity.com', 'ip4_224.0.0.1': 'all_systems_on_this_subnet', 'ip4_224.0.0.2': 'all_routers_on_this_subnet', 'ip4_224.0.0.13': 'all_pim_routers', 'ip4_224.0.0.22': 'multicast/IGMP', 'ip4_224.0.0.251': 'multicast/mDNS', 'ip4_224.0.0.252': 'multicast/LLMNR', 'ip4_224.0.1.40': 'multicast/cisco_rp_discovery', 'ip4_224.0.1.60': 'multicast/hp_device_discovery', 'ip4_239.255.255.250': 'multicast/uPNP_or_SSDP', 'ip4_255.255.255.255': 'broadcast',
         'ip6_2001:558:feed::1': 'public_dns/cdns01.comcast.net', 'ip6_2001:558:feed::2': 'public_dns/cdns02.comcast.net', 'ip6_2001:558:feed:443::98': 'public_dns/doh.xfinity.com',
         'ip6_::': 'address_unspecified', 'ip6_::1': 'localhost', 'ip6_ff02::1': 'multicast/all_nodes', 'ip6_ff02::2': 'multicast/all_routers', 'ip6_ff02::c': 'multicast/ssdp', 'ip6_ff02::16': 'multicast/MLDv2_capable_routers', 'ip6_ff02::fb': 'multicast/mDNSv6', 'ip6_ff02::1:2': 'multicast/DHCP_Relay_Agents_and_Servers', 'ip6_ff02::1:3': 'multicast/LLMNR',
         'proto_0': 'ip', 'proto_2': 'igmp', 'proto_47': 'gre', 'proto_50': 'esp', 'proto_51': 'ah', 'proto_58': 'ipv6_icmp', 'proto_103': 'pim',
         'udp_7': 'echo', 'udp_17': 'qotd', 'udp_19': 'chargen', 'udp_53': 'dns', 'udp_67': 'bootp/dhcp', 'udp_69': 'tftp', 'udp_88': 'kerberos',
         'udp_111': 'rpc', 'udp_123': 'ntp', 'udp_137': 'netbios/ns', 'udp_138': 'netbios/datagram', 'udp_161': 'snmp',
         'udp_389': 'ldap',
         'udp_443': 'https/quic',
         'udp_500': 'isakmp/ike', 'udp_514': 'syslog', 'udp_520': 'rip', 'udp_546': 'dhcpv6_client', 'udp_547': 'dhcpv6',
         'udp_1194': 'openvpn',
         'udp_1434': 'mssql_monitor', 'udp_1853': 'videoconf/gotowebinar', 'udp_1900': 'ssdp/upnp',
         'udp_1812': 'radius',
         'udp_3389': 'remote_desktop_protocol', 'udp_3478': 'webrtc', 'udp_3479': 'webrtc', 'udp_3480': 'webrtc', 'udp_3481': 'webrtc', 'udp_3702': 'web_services_discovery',
         'udp_4500': 'ipsec_nat_traversal', 'udp_4501': 'globalprotect_vpn', 'udp_4789': 'vxlan',
         'udp_5002': 'drobo_discovery', 'udp_5060': 'sip', 'udp_5353': 'mDNS', 'udp_5355': 'LLMNR', 'udp_5938': 'teamviewer',
         'udp_8200': 'videoconf/gotowebinar', 'udp_8801': 'videoconf/zoom', 'udp_8802': 'videoconf/zoom',
         'udp_15509': 'videoconf/zoom',
         'udp_17500': 'dropbox_lan_sync',
         'udp_19305': 'google_meet',
         'udp_33434': 'traceroute/udp', 'udp_33435': 'traceroute/udp', 'udp_33436': 'traceroute/udp', 'udp_33437': 'traceroute/udp', 'udp_33438': 'traceroute/udp', 'udp_33439': 'traceroute/udp',
         'udp_33440': 'traceroute/udp', 'udp_33441': 'traceroute/udp', 'udp_33442': 'traceroute/udp', 'udp_33443': 'traceroute/udp', 'udp_33444': 'traceroute/udp', 'udp_33445': 'traceroute/udp', 'udp_33446': 'traceroute/udp', 'udp_33447': 'traceroute/udp', 'udp_33448': 'traceroute/udp', 'udp_33449': 'traceroute/udp',
         'udp_33450': 'traceroute/udp', 'udp_33451': 'traceroute/udp', 'udp_33452': 'traceroute/udp', 'udp_33453': 'traceroute/udp', 'udp_33454': 'traceroute/udp', 'udp_33455': 'traceroute/udp', 'udp_33456': 'traceroute/udp', 'udp_33457': 'traceroute/udp', 'udp_33458': 'traceroute/udp', 'udp_33459': 'traceroute/udp',
         'udp_33460': 'traceroute/udp', 'udp_33461': 'traceroute/udp', 'udp_33462': 'traceroute/udp', 'udp_33463': 'traceroute/udp', 'udp_33464': 'traceroute/udp', 'udp_33465': 'traceroute/udp', 'udp_33466': 'traceroute/udp', 'udp_33467': 'traceroute/udp', 'udp_33468': 'traceroute/udp', 'udp_33469': 'traceroute/udp',
         'udp_33470': 'traceroute/udp', 'udp_33471': 'traceroute/udp', 'udp_33472': 'traceroute/udp', 'udp_33473': 'traceroute/udp', 'udp_33474': 'traceroute/udp', 'udp_33475': 'traceroute/udp', 'udp_33476': 'traceroute/udp', 'udp_33477': 'traceroute/udp', 'udp_33478': 'traceroute/udp', 'udp_33479': 'traceroute/udp',
         'udp_33480': 'traceroute/udp', 'udp_33481': 'traceroute/udp', 'udp_33482': 'traceroute/udp', 'udp_33483': 'traceroute/udp', 'udp_33484': 'traceroute/udp', 'udp_33485': 'traceroute/udp', 'udp_33486': 'traceroute/udp', 'udp_33487': 'traceroute/udp', 'udp_33488': 'traceroute/udp', 'udp_33489': 'traceroute/udp',
         'udp_33490': 'traceroute/udp', 'udp_33491': 'traceroute/udp', 'udp_33492': 'traceroute/udp', 'udp_33493': 'traceroute/udp', 'udp_33494': 'traceroute/udp', 'udp_33495': 'traceroute/udp', 'udp_33496': 'traceroute/udp', 'udp_33497': 'traceroute/udp', 'udp_33498': 'traceroute/udp', 'udp_33499': 'traceroute/udp',
         'udp_33500': 'traceroute/udp', 'udp_33501': 'traceroute/udp', 'udp_33502': 'traceroute/udp', 'udp_33503': 'traceroute/udp', 'udp_33504': 'traceroute/udp', 'udp_33505': 'traceroute/udp', 'udp_33506': 'traceroute/udp', 'udp_33507': 'traceroute/udp', 'udp_33508': 'traceroute/udp', 'udp_33509': 'traceroute/udp',
         'udp_33510': 'traceroute/udp', 'udp_33511': 'traceroute/udp', 'udp_33512': 'traceroute/udp', 'udp_33513': 'traceroute/udp', 'udp_33514': 'traceroute/udp', 'udp_33515': 'traceroute/udp', 'udp_33516': 'traceroute/udp', 'udp_33517': 'traceroute/udp', 'udp_33518': 'traceroute/udp', 'udp_33519': 'traceroute/udp',
         'udp_33520': 'traceroute/udp', 'udp_33521': 'traceroute/udp', 'udp_33522': 'traceroute/udp', 'udp_33523': 'traceroute/udp',
         'tcp_7': 'echo', 'tcp_11': 'systat', 'tcp_13': 'daytime', 'tcp_19': 'chargen', 'tcp_20': 'ftp-data', 'tcp_21': 'ftp', 'tcp_22': 'ssh', 'tcp_23': 'telnet', 'tcp_25': 'smtp', 'tcp_37': 'time', 'tcp_42': 'name', 'tcp_43': 'whois', 'tcp_53': 'dns', 'tcp_79': 'finger', 'tcp_80': 'http', 'tcp_88': 'kerberos',
         'tcp_109': 'pop2', 'tcp_110': 'pop3', 'tcp_111': 'rpc', 'tcp_113': 'ident/auth', 'tcp_119': 'nntp', 'tcp_135': 'ms_rpc_endpoint_mapper', 'tcp_139': 'netbios/session', 'tcp_143': 'imap', 'tcp_179': 'bgp',
         'tcp_389': 'ldap',
         'tcp_443': 'https', 'tcp_445': 'microsoft-ds', 'tcp_465': 'smtps',
         'tcp_512': 'r-commands/rexec', 'tcp_513': 'r-commands/rlogin', 'tcp_514': 'r-commands/rsh_rcp', 'tcp_587': 'smtp/msa',
         'tcp_631': 'ipp',
         'tcp_873': 'rsync',
         'tcp_989': 'ftps-data', 'tcp_990': 'ftps', 'tcp_993': 'imaps',
         'tcp_1194': 'openvpn',
         'tcp_1389': 'iclpv-dm_or_alt_jndi_ldap',
         'tcp_1433': 'mssql', 'tcp_1434': 'mssql_monitor',
         'tcp_1723': 'pptp',
         'tcp_1935': 'rtmp', 'tcp_1984': 'bigbrother',
         'tcp_3128': 'squid_proxy', 'tcp_3306': 'mysql', 'tcp_3389': 'remote_desktop_protocol', 'tcp_3478': 'webrtc',
         'tcp_5001': 'drobo/nasd', 'tcp_5060': 'sip', 'tcp_5223': 'apple_push_notification', 'tcp_5228': 'google_talk', 'tcp_5601': 'kibana', 'tcp_5900': 'vnc/remote_framebuffer', 'tcp_5938': 'teamviewer',
         'tcp_6379': 'redis',
         'tcp_7680': 'windows/delivery_optimization',
         'tcp_8008': 'apple_ical', 'tcp_8080': 'http-alt', 'tcp_8333': 'bitcoin',
         'tcp_9200': 'elasticsearch'}

#The following are _sub_layers; additional details underneath a main layer, such as SNMPBulk under SNMP.
ignore_layers = ('DHCP options',
		 'DHCP6 Client Identifier Option', 'DHCP6 Elapsed Time Option', 'DHCP6 Identity Association for Non-temporary Addresses Option', 'DHCP6 Option - Client FQDN', 'DHCP6 Option Request Option', 'DHCP6 Vendor Class Option',
		 'DNS DNSKEY Resource Record', 'DNS DS Resource Record', 'DNS EDNS0 TLV', 'DNS NSEC Resource Record', 'DNS NSEC3 Resource Record', 'DNS OPT Resource Record', 'DNS Question Record', 'DNS RRSIG Resource Record', 'DNS Resource Record', 'DNS SRV Resource Record',
		 'Ethernet',
		 'ICMPv6 Neighbor Discovery Option - Prefix Information', 'ICMPv6 Neighbor Discovery Option - Recursive DNS Server Option', 'ICMPv6 Neighbor Discovery Option - Route Information Option', 'ICMPv6 Neighbor Discovery Option - Source Link-Layer Address',
		 'IP Option End of Options List', 'IP Option No Operation',
                 'ISAKMP Identification', 'ISAKMP Key Exchange', 'ISAKMP Nonce', 'ISAKMP SA', 'ISAKMP Vendor ID', 'ISAKMP payload',
		 'PadN', 'Padding',
		 'Raw',
		 'SCTPChunkInit', 'SCTPChunkParamCookiePreservative', 'SCTPChunkParamSupportedAddrTypes',
		 'SNMPbulk', 'SNMPget', 'SNMPnext', 'SNMPvarbind',
		 'vendor_class_data')

#tcp_ignore_ports = (123, 20547, 33046, 39882)		#Was used for early troubleshooting, no longer needed.
#udp_ignore_ports = (10400, 10401, 16403, 38010)

ip_names_cache = os.environ["HOME"] + '/.cache/ip_names'

if __name__ == '__main__':
	import argparse

	parser = argparse.ArgumentParser(description='pcap_stats version ' + str(__version__))
	parser.add_argument('-i', '--interface', help='Interface from which to read packets', required=False, default=None)
	parser.add_argument('-r', '--read', help='Pcap file(s) from which to read packets', required=False, default=[], nargs='*')
	parser.add_argument('-d', '--devel', help='Enable development/debug statements', required=False, default=False, action='store_true')
	parser.add_argument('-b', '--bpf', help='BPF to restrict which packets are processed', required=False, default='')
	parser.add_argument('-c', '--count', help='Number of packets to sniff (if not specified, sniff forever/until end of pcap file)', type=int, required=False, default=None)
	parser.add_argument('-m', '--mincount', help='Only show a record if we have seen it this many times (default: %(default)s)', type=int, required=False, default=0)
	parser.add_argument('-s', '--minsize', help='Only show a record if have this many total bytes (default: %(default)s)', type=int, required=False, default=0)
	parser.add_argument('-l', '--length', help='Which form of length to use (default: %(default)s)', choices=('ip',), required=False, default='ip')		#Reinstate this when the length function accepts them:   , choices=('ip', 'layer', 'payload')
	parser.add_argument('-f', '--format', help='Output format (default: %(default)s)', choices=('ascii', 'html'), required=False, default='ascii')
	(parsed, unparsed) = parser.parse_known_args()
	cl_args = vars(parsed)


	#We have to use libpcap instead of scapy's built-in code because the latter won't attach complex bpfs
	try:
		conf.use_pcap = True
	except:
		config.use_pcap = True

	read_from_stdin = False		#If stdin requested, it needs to be processed last, so we remember it here.  We also handle the case where the user enters '-' more than once by simply remembering it.
	if cl_args['interface'] and cl_args['read']:
		data_source = str(cl_args['interface']) + ' ' + str(cl_args['read'])
	elif cl_args['interface']:
		data_source = str(cl_args['interface'])
	elif cl_args['read']:
		data_source = str(cl_args['read'])
	else:
		#elif cl_args['interface'] is None and cl_args['read'] == []:
		debug_out('No source specified, reading from stdin.')
		read_from_stdin = True
		data_source = 'stdin'



	try:
		if cl_args['read']:
			#Process normal files first.
			for one_source in cl_args['read']:
				if one_source == '-':
					read_from_stdin = True
				else:
					process_packet_source(None, one_source, cl_args)

		#Now that normal files are out of the way process stdin and/or reading from an interface, either of which could be infinite.
		if read_from_stdin:
			process_packet_source(None, '-', cl_args)

		if cl_args['interface']:
			process_packet_source(cl_args['interface'], None, cl_args)
	except KeyboardInterrupt:
		pass

	print_stats(cl_args['mincount'], cl_args['minsize'], cl_args['format'], data_source)
