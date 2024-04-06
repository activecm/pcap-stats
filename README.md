# pcap-stats

Learn about a network from a pcap file or reading from an interface. 
This tool focuses on the traffic types with the largest number of packets
or bytes, allowing you to identify traffic spikes, DOS or DDOS attacks,
bandwidth hogs, and unwanted servers on your network.  For each line of
statistics we include the number of packets, the number of bytes, the
associated BPF to show just this traffic, and one or more hints as to
what this traffic might be (including the ports used, hostnames and
netbios names, and address type details.

"Traffic types" include IP and physical layers, protocol layers, TCP
flags, ICMP types, TCP and UDP ports, individual IP addresses, hostnames,
and netbios names.  hostnames and netbios names are cached between runs.

# Quickstart
- If you don't have pip3 installed, install it with
```sudo apt install python3-pip``` or ```sudo yum install python3-pip```
- Install scapy with
```sudo pip3 install scapy```
- Analyze a pcap file with
```./pcap_stats.py -r pcap_file_name.pcap | less -S```
- Analyze packets coming in on a network interface with
```sudo ./pcap_stats.py -i eth0 -c 10000 | less -S```
- To create an HTML page of output
```./pcap_stats.py -r pcap_file_name.pcap -f html >pcap_stats.html```
- To see the other available options, run ```./pcap_stats.py -h```


# Tools
- In the text format, to see just the lines with more than 4000 packets:
```cat output.txt | awk '$1 > 4000 {print}' | less

- In the text format, to sort the output so the most common traffic is at the bottom:
```cat output.txt | sort -n | less

- In the text format, to sort the output so the most common traffic is at the top:
```cat output.txt | sort -nr | less
