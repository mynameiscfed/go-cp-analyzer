# Go Captured Packet Analyzer

A small tool that uses the go-packet library to analyze a packet capture and print out statistics about it.

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
