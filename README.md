# pcap-stats
Learn about a network from a pcap file or reading from an interface

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
```./pcap_stats.py -r pcap_file_name.pcap &gt;pcap_stats.html```
- To see the other available options, run ```./pcap_stats.py -h```
