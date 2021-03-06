# Go Captured Packet Analyzer

A small tool that uses the [gopacket](https://github.com/google/gopacket) library to analyze a packet capture and print out statistics about it.

## Features

* Packet size frequency
* Packet metrics
    * total packets
    * average packet size
    * average packets per second (pps)
    * total bytes, average throughput (Mbps)
* Protocol metrics
    * Ethernet
    * TCP
    * UDP
    * IPv4
    * IPv6
* Connections metrics
    * total TCP connections
    * average TCP connections per second
    * peak TCP connections per second
    * total UDP connections (no UDP timeout currently implemented)
    * UDP connections per second
    * peak UDP connections per second
* Connection state table
* Top N
    * Top connections by bytes
    * Top source IP addresses
    * Top destination IP addresses
    
## Usage
### Required

Filename 

-r <filename>

### Optional

Top N

-n <integer>

Print connection table

-c

## Example Output


```

shell> ./go-cp-analyzer -r test.pcap -c  -n 10

+----------------------------------+
|         go-pcapmon v.001         |
+----------------------+-----------+
| Packet Distribution  | ++++++++  |
+----------------------+-----------+
|  <= 66               | 11219     |
|  <= 128              | 729       |
|  <= 256              | 207       |
|  <= 384              | 131       |
|  <= 512              | 671       |
|  <= 768              | 508       |
|  <= 1024             | 281       |
|  <= 1518             | 1199      |
|  <= 9000             | 77757     |
+----------------------+-----------+
| Packet Metrics       | ++++++++  |
+----------------------+-----------+
| Total pkts           | 92702     |
| Avg pkt size         | 1311      |
| Avg pkts/second      | 2990      |
| Total bytes          | 121574142 |
| Avg thoughput (Mbps) | 31.37     |
+----------------------+-----------+
| Protocol Metrics     | ++++++++  |
+----------------------+-----------+
| Ethernet             | 92702     |
| TCP                  | 92542     |
| UDP                  | 88        |
| !Ethernet            | 0         |
| ARP                  | 72        |
| IPv4                 | 92630     |
+----------------------+-----------+
| Connections Metrics  | ++++++++  |
+----------------------+-----------+
| TCP connections      | 11        |
| TCP conns/sec (avg)  | 0         |
| TCP peak conns/sec   | 4         |
| UDP connections      | 8         |
| UDP conns/sec (avg)  | 0         |
| UDP peak conns/sec   | 2         |
+----------------------+-----------+

+------------------------------------------------------------------------------+
|                           Top Connections by Bytes                           |
+-----------+---------+---------------+-------+----------------+-------+-------+
| Bytes     | Packets | Source        | sPort | Destination    | dPort | Proto |
+-----------+---------+---------------+-------+----------------+-------+-------+
| 120684797 | 90438   | 192.168.1.154 | 54961 | 149.28.248.249 | 443   | 6     |
| 9703      | 31      | 192.168.1.40  | 54915 | 192.168.1.255  | 54915 | 17    |
| 8101      | 40      | 192.168.1.154 | 54974 | 216.58.210.14  | 443   | 6     |
| 6103      | 25      | 192.168.1.154 | 54973 | 216.58.207.42  | 443   | 6     |
| 5974      | 15      | 192.168.1.154 | 54966 | 216.58.208.35  | 443   | 6     |
| 5643      | 23      | 192.168.1.154 | 54972 | 209.87.211.155 | 443   | 6     |
| 5643      | 23      | 192.168.1.154 | 54971 | 209.87.211.155 | 443   | 6     |
| 5539      | 22      | 192.168.1.154 | 54965 | 104.26.5.115   | 443   | 6     |
| 5059      | 16      | 192.168.1.154 | 54960 | 149.28.248.249 | 443   | 6     |
+-----------+---------+---------------+-------+----------------+-------+-------+

+----------------------+
| Top Src IP Addresses |
+----+-----------------+
| 13 | 192.168.1.154   |
| 1  | 192.168.1.12    |
| 1  | 192.168.1.251   |
| 1  | 192.168.1.89    |
| 1  | 192.168.1.60    |
| 1  | 192.168.1.40    |
+----+-----------------+

+----------------------+
| Top Dst IP Addresses |
+---+------------------+
| 4 | 192.168.1.255    |
| 2 | 88.221.155.231   |
| 2 | 255.255.255.255  |
| 2 | 209.87.211.155   |
| 2 | 149.28.248.249   |
| 1 | 216.58.208.35    |
| 1 | 82.166.201.168   |
| 1 | 216.58.210.14    |
| 1 | 104.26.5.115     |
+---+------------------+

src 					 sport 	 dst 					 dport 	 proto 	 bytes 		 pkts
+------------------------------------+ 	 +---+ 	 +------------------------------------+  +---+ 	 +---+ 	 +---+ 		 +---+
192.168.1.60 				 137 	 192.168.1.255 				 137 	 17 	 2600 		 26
+------------------------------------+ 	 +---+ 	 +------------------------------------+  +---+ 	 +---+ 	 +---+ 		 +---+
192.168.1.154 				 54964 	 82.166.201.168 			 80 	 6 	 1929 		 10
+------------------------------------+ 	 +---+ 	 +------------------------------------+  +---+ 	 +---+ 	 +---+ 		 +---+
192.168.1.154 				 54974 	 216.58.210.14 				 443 	 6 	 8101 		 40
+------------------------------------+ 	 +---+ 	 +------------------------------------+  +---+ 	 +---+ 	 +---+ 		 +---+
192.168.1.40 				 54915 	 192.168.1.255 				 54915 	 17 	 9703 		 31
+------------------------------------+ 	 +---+ 	 +------------------------------------+  +---+ 	 +---+ 	 +---+ 		 +---+
192.168.1.154 				 54962 	 88.221.155.231 			 443 	 6 	 1719 		 14
+------------------------------------+ 	 +---+ 	 +------------------------------------+  +---+ 	 +---+ 	 +---+ 		 +---+
192.168.1.154 				 54963 	 88.221.155.231 			 443 	 6 	 1719 		 14
+------------------------------------+ 	 +---+ 	 +------------------------------------+  +---+ 	 +---+ 	 +---+ 		 +---+
192.168.1.154 				 54972 	 209.87.211.155 			 443 	 6 	 5643 		 23
+------------------------------------+ 	 +---+ 	 +------------------------------------+  +---+ 	 +---+ 	 +---+ 		 +---+
192.168.1.12 				 68 	 255.255.255.255 			 67 	 17 	 350 		 1
+------------------------------------+ 	 +---+ 	 +------------------------------------+  +---+ 	 +---+ 	 +---+ 		 +---+
192.168.1.154 				 52573 	 194.29.32.129 				 4500 	 17 	 4204 		 18
+------------------------------------+ 	 +---+ 	 +------------------------------------+  +---+ 	 +---+ 	 +---+ 		 +---+
192.168.1.154 				 54961 	 149.28.248.249 			 443 	 6 	 120684797 	 90438
+------------------------------------+ 	 +---+ 
```