#!/usr/bin/env python3
"""Print statistics of a pcap file or packets arriving on an interface."""



__version__ = '0.0.18'

__author__ = 'William Stearns'
__copyright__ = 'Copyright 2021, William Stearns'
__credits__ = ['William Stearns']
__email__ = 'william.l.stearns@gmail.com'
__license__ = 'GPL 3.0'
__maintainer__ = 'William Stearns'
__status__ = 'Prototype'				#Prototype, Development or Production



import os
import sys
import time
#from scapy.all import *
from scapy.all import ARP, Ether, ICMP, IP, IPv6, LLC, Scapy_Exception, STP, TCP, UDP, sniff				# pylint: disable=no-name-in-module



def debug_out(output_string):
	"""Send debuging output to stderr."""

	if cl_args['devel']:
		sys.stderr.write(output_string + '\n')
		sys.stderr.flush()


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


def packet_len(packet, whichlayer):
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


def processpacket(p):
	"""Extract statistics from a single packet."""

	if "p_stats" not in processpacket.__dict__:
		processpacket.p_stats = {'count': [0, 0]}

	if "field_filter" not in processpacket.__dict__:
		processpacket.field_filter = {'count': '', 'ARP': 'arp', 'ESP': 'ip proto esp', 'IP': 'ip', 'ICMP': 'icmp', 'IPv6': 'ip6', 'TCP': 'tcp', 'UDP': 'udp', '802.1Q': 'vlan',
		'TCP_FLAGS_': 'tcp[12:2] & 0x01ff = 0x0000', 'TCP_FLAGS_S': 'tcp[12:2] & 0x01ff = 0x0002', 'TCP_FLAGS_R': 'tcp[12:2] & 0x01ff = 0x0004', 'TCP_FLAGS_SR': 'tcp[12:2] & 0x01ff = 0x0006', 'TCP_FLAGS_RP': 'tcp[12:2] & 0x01ff = 0x000C',
		'TCP_FLAGS_A': 'tcp[12:2] & 0x01ff = 0x0010', 'TCP_FLAGS_FA': 'tcp[12:2] & 0x01ff = 0x0011', 'TCP_FLAGS_SA': 'tcp[12:2] & 0x01ff = 0x0012', 'TCP_FLAGS_RA': 'tcp[12:2] & 0x01ff = 0x0014', 'TCP_FLAGS_FRA': 'tcp[12:2] & 0x01ff = 0x0015', 'TCP_FLAGS_PA': 'tcp[12:2] & 0x01ff = 0x0018', 'TCP_FLAGS_FPA': 'tcp[12:2] & 0x01ff = 0x0019', 'TCP_FLAGS_RPA': 'tcp[12:2] & 0x01ff = 0x001C',
		'TCP_FLAGS_U': 'tcp[12:2] & 0x01ff = 0x0020', 'TCP_FLAGS_SU': 'tcp[12:2] & 0x01ff = 0x0022', 'TCP_FLAGS_FPU': 'tcp[12:2] & 0x01ff = 0x0029', 'TCP_FLAGS_FSPU': 'tcp[12:2] & 0x01ff = 0x002b',
		'TCP_FLAGS_SAU': 'tcp[12:2] & 0x01ff = 0x0032', 'TCP_FLAGS_FSRPAU': 'tcp[12:2] & 0x01ff = 0x003f',
		'TCP_FLAGS_FAE': 'tcp[12:2] & 0x01ff = 0x0051', 'TCP_FLAGS_SAE': 'tcp[12:2] & 0x01ff = 0x0052',
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
		processpacket.tcp_server_ports = [7, 13, 21, 22, 23, 25, 53, 79, 80, 88, 110, 111, 113, 135, 139, 143, 389, 443, 445, 514, 902, 990, 993, 995, 1433, 1521, 1723, 3128, 3306, 3389, 5000, 5060, 5223, 5228, 5432, 5601, 5900, 7070, 8008, 8009, 8080, 8088, 8443, 9200, 9443]

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


	p_layers = packet_layers(p)


	if p.haslayer(IP):
		i_layer = p.getlayer(IP)
		p_len = packet_len(p, IP)
		proto = str(i_layer.proto)
		ttl = int(i_layer.ttl)
		sIP = i_layer.src
		dIP = i_layer.dst
		label = 'ip4_' + sIP
		if label not in processpacket.p_stats:
			processpacket.p_stats[label] = [0, 0]
		processpacket.p_stats[label][0] += 1
		processpacket.p_stats[label][1] += p_len
		processpacket.field_filter[label] = 'host ' + sIP
		label = 'ip4_' + dIP
		if label not in processpacket.p_stats:
			processpacket.p_stats[label] = [0, 0]
		processpacket.p_stats[label][0] += 1
		processpacket.p_stats[label][1] += p_len
		processpacket.field_filter[label] = 'host ' + dIP
	elif p.haslayer(IPv6):
		i_layer = p.getlayer(IPv6)
		p_len = packet_len(p, IPv6)
		proto = str(i_layer.nh)
		ttl = int(i_layer.hlim)
		sIP = i_layer.src
		dIP = i_layer.dst
		label = 'ip6_' + sIP
		if label not in processpacket.p_stats:
			processpacket.p_stats[label] = [0, 0]
		processpacket.p_stats[label][0] += 1
		processpacket.p_stats[label][1] += p_len
		processpacket.field_filter[label] = 'host ' + sIP
		label = 'ip6_' + dIP
		if label not in processpacket.p_stats:
			processpacket.p_stats[label] = [0, 0]
		processpacket.p_stats[label][0] += 1
		processpacket.p_stats[label][1] += p_len
		processpacket.field_filter[label] = 'host ' + dIP
	elif p.haslayer(ARP):
		i_layer = None
		p_len = packet_len(p, ARP)
		proto = None
		ttl = -1
		sIP = p.getlayer(ARP).psrc
		dIP = p.getlayer(ARP).pdst
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
		p.show()
		sys.exit(99)
		i_layer = None
		p_len = 0		#FIXME
		proto = None
		ttl = -1
		sIP = None
		dIP = None

	processpacket.p_stats['count'][0] += 1
	processpacket.p_stats['count'][1] += p_len
	#sys.stderr.write('.')

	if sIP and sIP != '0.0.0.0' and ':' not in sIP and not sIP.startswith('169.254.') and p.haslayer(Ether):	#We remember all the IPv4 addresses associated with a particular mac to decide later whether a mac address is a router.
		sMAC = p.getlayer(Ether).src
		if sMAC not in processpacket.ipv4s_for_mac:
			processpacket.ipv4s_for_mac[sMAC] = set([])
		processpacket.ipv4s_for_mac[sMAC].add(sIP)

	for a_layer in p_layers:
		if a_layer not in ignore_layers:
			if a_layer not in processpacket.p_stats:
				processpacket.p_stats[a_layer] = [0, 0]
			processpacket.p_stats[a_layer][0] += 1
			processpacket.p_stats[a_layer][1] += p_len



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
			sys.exit(99)

	#Good for debugging
	#if sIP and ttl != -1:
	#	label = 'ipttl_' + sIP + '_' + str(ttl)
	#	if label not in processpacket.p_stats:
	#		processpacket.p_stats[label] = [0, 0]
	#	processpacket.p_stats[label][0] += 1
	#	processpacket.p_stats[label][1] += p_len
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
		#sys.exit(99)


		if t_layer.flags == 'S' and t_layer.dport not in processpacket.tcp_server_ports:	#Following blocks try to identify which end is the "server" port.
			debug_out("Adding " + str(t_layer.dport) + " to tcp_server_ports")
			processpacket.tcp_server_ports.append(t_layer.dport)
		elif t_layer.flags == 'SA' and t_layer.sport not in processpacket.tcp_server_ports:
			debug_out("Adding " + str(t_layer.sport) + " to tcp_server_ports")
			processpacket.tcp_server_ports.append(t_layer.sport)

		if t_layer.sport in processpacket.tcp_server_ports:
			label = 'tcp_' + str(t_layer.sport)
			if label not in processpacket.p_stats:
				processpacket.p_stats[label] = [0, 0]
			processpacket.p_stats[label][0] += 1
			processpacket.p_stats[label][1] += p_len
			processpacket.field_filter[label] = 'tcp port ' + str(t_layer.sport)
		elif t_layer.dport in processpacket.tcp_server_ports:
			label = 'tcp_' + str(t_layer.dport)
			if label not in processpacket.p_stats:
				processpacket.p_stats[label] = [0, 0]
			processpacket.p_stats[label][0] += 1
			processpacket.p_stats[label][1] += p_len
			processpacket.field_filter[label] = 'tcp port ' + str(t_layer.dport)
		elif t_layer.sport in tcp_ignore_ports and t_layer.dport in tcp_ignore_ports:
			pass
		else:
			debug_out("No tcp server port: " + str(t_layer.sport) + " " + str(t_layer.dport))
			#p.show()
			#sys.exit(99)

		label = 'TCP_FLAGS_' + str(t_layer.flags)
		if label not in processpacket.p_stats:
			processpacket.p_stats[label] = [0, 0]
		processpacket.p_stats[label][0] += 1
		processpacket.p_stats[label][1] += p_len

	elif p.haslayer(UDP):
		u_layer = p.getlayer(UDP)
		if u_layer.sport in processpacket.udp_server_ports:					#Following blocks try to identify which end is the "server" port.
			label = 'udp_' + str(u_layer.sport)
			if label not in processpacket.p_stats:
				processpacket.p_stats[label] = [0, 0]
			processpacket.p_stats[label][0] += 1
			processpacket.p_stats[label][1] += p_len
			processpacket.field_filter[label] = 'udp port ' + str(u_layer.sport)
		elif u_layer.dport in processpacket.udp_server_ports:
			label = 'udp_' + str(u_layer.dport)
			if label not in processpacket.p_stats:
				processpacket.p_stats[label] = [0, 0]
			processpacket.p_stats[label][0] += 1
			processpacket.p_stats[label][1] += p_len
			processpacket.field_filter[label] = 'udp port ' + str(u_layer.dport)
		elif u_layer.sport >= 33434 and u_layer.sport < 33524:					#Special case traceroute if we didn't find it in the fixed ports above
			label = 'udp_' + str(u_layer.sport)
			if label not in processpacket.p_stats:
				processpacket.p_stats[label] = [0, 0]
			processpacket.p_stats[label][0] += 1
			processpacket.p_stats[label][1] += p_len
			processpacket.field_filter[label] = 'udp port ' + str(u_layer.sport)
		elif u_layer.dport >= 33434 and u_layer.dport < 33524:
			label = 'udp_' + str(u_layer.dport)
			if label not in processpacket.p_stats:
				processpacket.p_stats[label] = [0, 0]
			processpacket.p_stats[label][0] += 1
			processpacket.p_stats[label][1] += p_len
			processpacket.field_filter[label] = 'udp port ' + str(u_layer.dport)
		elif u_layer.sport in udp_ignore_ports and u_layer.dport in udp_ignore_ports:
			pass
		else:
			label = 'udp_' + str(u_layer.sport)
			if label not in processpacket.p_stats:
				processpacket.p_stats[label] = [0, 0]
			processpacket.p_stats[label][0] += 1
			processpacket.p_stats[label][1] += p_len
			processpacket.field_filter[label] = 'udp port ' + str(u_layer.sport)
			label = 'udp_' + str(u_layer.dport)
			if label not in processpacket.p_stats:
				processpacket.p_stats[label] = [0, 0]
			processpacket.p_stats[label][0] += 1
			processpacket.p_stats[label][1] += p_len
			processpacket.field_filter[label] = 'udp port ' + str(u_layer.dport)

			#debug_out("No udp server port")
			#p.show()
			#sys.exit(99)
	elif p.haslayer(ICMP):
		i_layer = p.getlayer(ICMP)
		label = 'icmp_' + str(i_layer.type) + '.' + str(i_layer.code)
		if label not in processpacket.p_stats:
			processpacket.p_stats[label] = [0, 0]
		processpacket.p_stats[label][0] += 1
		processpacket.p_stats[label][1] += p_len
		processpacket.field_filter[label] = 'icmptype = ' + str(i_layer.type) + ' and icmpcode = ' + str(i_layer.code)
		#p.show()
		#sys.exit(99)
	#Come back for this - it takes a lot of individual headers
	#elif p.haslayer(ICMPv6):					#use icmp6type and icmp6code
	#	i_layer = p.getlayer(ICMPv6)
	#	p.show()
	#	sys.exit(99)
	#	label = 'icmp_' + str(i_layer.type) + '.' + str(i_layer.code)
	#	if label not in processpacket.p_stats:
	#		processpacket.p_stats[label] = [0, 0]
	#	processpacket.p_stats[label][0] += 1
	elif p.haslayer(ARP) or p.haslayer(LLC):
		pass
	elif proto:
		label = 'proto_' + str(proto)
		if label not in processpacket.p_stats:
			processpacket.p_stats[label] = [0, 0]
		processpacket.p_stats[label][0] += 1
		processpacket.p_stats[label][1] += p_len
		processpacket.field_filter[label] = 'ip proto ' + str(proto)

	elif p.haslayer(IPv6):						#use "ip6 proto"
		pass							#FIXME
	elif p_layers == ['Ethernet', 'Raw']:
		pass
	else:
		debug_out("Non-udp-tcp")
		p.show()
		sys.exit(99)


def print_stats(minimum_to_show):
	"""Show statistics"""

	if "p_stats" in processpacket.__dict__:
		for one_key in sorted(processpacket.p_stats.keys()):
			if processpacket.p_stats[one_key][0] > minimum_to_show:
				desc = one_key.replace(' ', '_')
				orig_ip = desc.replace('ip4_', '').replace('ip6_', '')
				is_local = ''
				if orig_ip in processpacket.local_ips:
					is_local = ' local'

					for one_mac in processpacket.ipv4s_for_mac.keys():
						if orig_ip in processpacket.ipv4s_for_mac[one_mac] and len(processpacket.ipv4s_for_mac[one_mac]) > 1:
							is_local = ' local ipv4router' + ' ' + str(processpacket.ipv4s_for_mac[one_mac])

				if desc in hints:
					print("{0:>10d} {1:>13d} {2:60s} {3:48s} {4:30s}".format(processpacket.p_stats[one_key][0], processpacket.p_stats[one_key][1], desc, processpacket.field_filter.get(one_key, ''), hints[desc] + is_local))
				elif desc.startswith(('ip4_169.254.',)):
					print("{0:>10d} {1:>13d} {2:60s} {3:48s} {4:30s}".format(processpacket.p_stats[one_key][0], processpacket.p_stats[one_key][1], desc, processpacket.field_filter.get(one_key, ''), 'link_local/unable_to_get_address' + is_local))
				elif desc.startswith(('ip6_fe80:')):
					print("{0:>10d} {1:>13d} {2:60s} {3:48s} {4:30s}".format(processpacket.p_stats[one_key][0], processpacket.p_stats[one_key][1], desc, processpacket.field_filter.get(one_key, ''), 'link_local_address' + is_local))
				elif desc.startswith(('ip4_10.', 'ip4_172.16.', 'ip4_172.17.', 'ip4_172.18.', 'ip4_172.19.', 'ip4_172.20.', 'ip4_172.21.', 'ip4_172.22.', 'ip4_172.23.', 'ip4_172.24.', 'ip4_172.25.', 'ip4_172.26.', 'ip4_172.27.', 'ip4_172.28.', 'ip4_172.29.', 'ip4_172.30.', 'ip4_172.31.', 'ip4_192.168.')):
					print("{0:>10d} {1:>13d} {2:60s} {3:48s} {4:30s}".format(processpacket.p_stats[one_key][0], processpacket.p_stats[one_key][1], desc, processpacket.field_filter.get(one_key, ''), 'rfc1918/reserved' + is_local))
				elif desc.startswith(('ip4_17.')):
					print("{0:>10d} {1:>13d} {2:60s} {3:48s} {4:30s}".format(processpacket.p_stats[one_key][0], processpacket.p_stats[one_key][1], desc, processpacket.field_filter.get(one_key, ''), 'apple' + is_local))
				elif desc.startswith(('ip4_73.')):
					print("{0:>10d} {1:>13d} {2:60s} {3:48s} {4:30s}".format(processpacket.p_stats[one_key][0], processpacket.p_stats[one_key][1], desc, processpacket.field_filter.get(one_key, ''), 'comcast' + is_local))
				else:
					print("{0:>10d} {1:>13d} {2:60s} {3:48s} {4:30s}".format(processpacket.p_stats[one_key][0], processpacket.p_stats[one_key][1], desc, processpacket.field_filter.get(one_key, ''), is_local))

		#print(processpacket.p_stats)
		print("Local_IPs: " + str(sorted(processpacket.local_ips)))

		#print(processpacket.minstamp)
		print("T_Begin: " + time.asctime(time.gmtime(processpacket.minstamp)))
		#print(processpacket.maxstamp)
		print("T_End: " + time.asctime(time.gmtime(processpacket.maxstamp)))

		print("T_Elapsed: " + str(processpacket.maxstamp - processpacket.minstamp))


hints = {'TCP_FLAGS_': 'Invalid/no_tcp_flags', 'TCP_FLAGS_SR': 'Invalid/syn_and_rst', 'TCP_FLAGS_FRA': 'Invalid/fin_and_rst', 'TCP_FLAGS_FSPEC': 'Invalid/fin_and_syn', 'TCP_FLAGS_FSPU': 'Invalid/fin_and_syn', 'TCP_FLAGS_FSRPAU': 'Invalid/fin_and_syn_and_rst', 'TCP_FLAGS_FSRPAUEN': 'Invalid/fin_and_syn_and_rst_christmas_tree',
         'icmp_0.0': 'echo_reply',
         'icmp_3.0': 'unreachable/net', 'icmp_3.1': 'unreachable/host', 'icmp_3.10': 'unreachable/host_admin_prohib', 'icmp_3.13': 'unreachable/communication_administratively_prohibited', 'icmp_3.2': 'unreachable/protocol', 'icmp_3.3': 'unreachable/port', 'icmp_3.4': 'unreachable/frag_needed_and_df_set',
         'icmp_5.0': 'redirect/net', 'icmp_5.1': 'redirect/host', 'icmp_5.2': 'redirect/tos_and_net', 'icmp_5.3': 'redirect/tos_and_host',
         'icmp_8.0': 'echo_request',
         'icmp_9.0': 'router_advertisement/normal',
         'icmp_11.0': 'time_exceeded/TTL',
         'icmp_13.0': 'timestamp',
         'icmp_14.0': 'timestamp_reply',
         'ip4_0.0.0.0': 'address_unspecified', 'ip4_1.1.1.1': 'public_dns/cloudflare', 'ip4_127.0.0.1': 'localhost', 'ip4_8.8.4.4': 'public_dns/google', 'ip4_8.8.8.8': 'public_dns/google', 'ip4_224.0.0.1': 'all_systems_on_this_subnet', 'ip4_224.0.0.2': 'all_routers_on_this_subnet', 'ip4_224.0.0.13': 'all_pim_routers', 'ip4_224.0.0.22': 'multicast/IGMP', 'ip4_224.0.0.251': 'multicast/mDNS', 'ip4_224.0.0.252': 'multicast/LLMNR', 'ip4_224.0.1.40': 'multicast/cisco_rp_discovery', 'ip4_224.0.1.60': 'multicast/hp_device_discovery', 'ip4_239.255.255.250': 'multicast/uPNP_or_SSDP', 'ip4_255.255.255.255': 'broadcast',
         'ip6_::': 'address_unspecified', 'ip6_::1': 'localhost', 'ip6_ff02::1': 'multicast/all_nodes', 'ip6_ff02::2': 'multicast/all_routers', 'ip6_ff02::c': 'multicast/ssdp', 'ip6_ff02::16': 'multicast/MLDv2_capable_routers', 'ip6_ff02::fb': 'multicast/mDNSv6', 'ip6_ff02::1:2': 'multicast/DHCP_Relay_Agents_and_Servers', 'ip6_ff02::1:3': 'multicast/LLMNR',
         'proto_2': 'igmp', 'proto_47': 'gre', 'proto_50': 'esp', 'proto_51': 'ah', 'proto_103': 'pim',
         'udp_7': 'echo', 'udp_17': 'qotd', 'udp_19': 'chargen', 'udp_53': 'dns', 'udp_67': 'bootp/dhcp', 'udp_69': 'tftp', 'udp_88': 'kerberos',
         'udp_111': 'rpc', 'udp_123': 'ntp', 'udp_137': 'netbios/ns', 'udp_138': 'netbios/datagram', 'udp_161': 'snmp',
         'udp_389': 'ldap',
         'udp_443': 'https/quic',
         'udp_500': 'isakmp/ike', 'udp_514': 'syslog', 'udp_520': 'rip', 'udp_546': 'dhcpv6_client', 'udp_547': 'dhcpv6',
         'udp_1194': 'openvpn',
         'udp_1434': 'mssql_monitor', 'udp_1900': 'ssdp/upnp',
         'udp_3389': 'remote_desktop_protocol', 'udp_3702': 'web_services_discovery',
         'udp_4500': 'ipsec_nat_traversal', 'udp_4789': 'vxlan',
         'udp_5060': 'sip', 'udp_5353': 'mDNS', 'udp_5355': 'LLMNR', 'udp_5938': 'teamviewer',
         'udp_17500': 'dropbox_lan_sync',
         'udp_19305': 'google_meet',
         'tcp_7': 'echo', 'tcp_11': 'systat', 'tcp_19': 'chargen', 'tcp_20': 'ftp-data', 'tcp_21': 'ftp', 'tcp_22': 'ssh', 'tcp_23': 'telnet', 'tcp_25': 'smtp', 'tcp_43': 'whois', 'tcp_53': 'dns', 'tcp_79': 'finger', 'tcp_80': 'http', 'tcp_88': 'kerberos',
         'tcp_109': 'pop2', 'tcp_110': 'pop3', 'tcp_111': 'rpc', 'tcp_113': 'ident/auth', 'tcp_135': 'ms_rpc_endpoint_mapper', 'tcp_143': 'imap', 'tcp_179': 'bgp',
         'tcp_389': 'ldap',
         'tcp_443': 'https', 'tcp_445': 'microsoft-ds', 'tcp_465': 'smtps',
         'tcp_587': 'smtp/msa',
         'tcp_873': 'rsync',
         'tcp_989': 'ftps-data', 'tcp_990': 'ftps', 'tcp_993': 'imaps',
         'tcp_1194': 'openvpn',
         'tcp_1433': 'mssql', 'tcp_1434': 'mssql_monitor',
         'tcp_1723': 'pptp',
         'tcp_1984': 'bigbrother',
         'tcp_3128': 'squid_proxy', 'tcp_3306': 'mysql', 'tcp_3389': 'remote_desktop_protocol',
         'tcp_5223': 'apple_push_notification', 'tcp_5060': 'sip', 'tcp_5900': 'remote_framebuffer', 'tcp_5938': 'teamviewer',
         'tcp_6379': 'redis',
         'tcp_8008': 'apple_ical', 'tcp_8333': 'bitcoin',
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

tcp_ignore_ports = (123, 20547, 33046, 39882)
udp_ignore_ports = (10400, 10401, 16403, 38010)


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
	parser.add_argument('-l', '--length', help='Which form of length to use (default: %(default)s)', choices=('ip'), required=False, default='ip')		#Reinstate this when the length function accepts them:   , choices=('ip', 'layer', 'payload')
	(parsed, unparsed) = parser.parse_known_args()
	cl_args = vars(parsed)

	try:
		if cl_args['interface']:
			try:
				if cl_args['count']:
					sniff(store=0, iface=cl_args['interface'], filter=cl_args['bpf'], count=cl_args['count'], prn=lambda x: processpacket(x))	# pylint: disable=unnecessary-lambda
				else:
					sniff(store=0, iface=cl_args['interface'], filter=cl_args['bpf'], prn=lambda x: processpacket(x))				# pylint: disable=unnecessary-lambda
			except Scapy_Exception:
				debug_out('Attempt to listen on an interface failed: are you running this as root or under sudo?')
			sys.stderr.write('\n')
			sys.stderr.flush()
		elif cl_args['read']:
			for one_pcap in cl_args['read']:
				if os.path.exists(one_pcap):
					if os.access(one_pcap, os.R_OK):
						if cl_args['count']:
							sniff(store=0, offline=one_pcap, filter=cl_args['bpf'], count=cl_args['count'], prn=lambda x: processpacket(x))	# pylint: disable=unnecessary-lambda
						else:
							sniff(store=0, offline=one_pcap, filter=cl_args['bpf'], prn=lambda x: processpacket(x))				# pylint: disable=unnecessary-lambda
					else:
						debug_out(str(one_pcap) + ' unreadable, skipping.')
				else:
					debug_out(one_pcap + " does not appear to exist, skipping.")
			sys.stderr.write('\n')
			sys.stderr.flush()
		else:
			debug_out("No interface or pcap file specified, exiting.")
			sys.exit(1)
	except KeyboardInterrupt:
		pass

	print_stats(cl_args['mincount'])
