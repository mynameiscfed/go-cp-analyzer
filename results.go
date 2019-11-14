package main

import (
	"fmt"
	"sort"

	"github.com/mynameiscfed/termtables"
)

type intPair struct {
	Key   int
	Value int
}

type intPairList []intPair

type stringPair struct {
	Key   string
	Value int
}

type stringPairList []stringPair

//printResults prints the final results
func printResults() {

	// Find first and last packet times
	var e []int
	for f := range ppsStats {
		e = append(e, f)
	}
	sort.Ints(e)

	firstPacketTime := e[0]
	lastPacketTime := e[len(e)-1]
	totalTime := lastPacketTime - firstPacketTime

	// Sort packetLengthStats
	var a []int
	for b := range packetLengthStats {
		a = append(a, b)
	}
	sort.Ints(a)

	// Create table of results
	resultsTable := termtables.CreateTable()
	resultsTable.AddTitle("go-pcapmon v.001")
	resultsTable.AddRow("Packet Distribution", "++++++++")
	resultsTable.AddSeparator()
	for _, i := range a {
		b := fmt.Sprintf(" <= %d", i)
		resultsTable.AddRow(b, packetLengthStats[i])
	}

	totalPackets := 0

	for _, j := range ppsStats {
		totalPackets += j
	}

	packetRate := totalPackets / totalTime
	averagePacketSize := totalBytes / totalPackets
	averageThrougput := totalBytes / totalTime

	// Create packet stats table
	resultsTable.AddSeparator()
	resultsTable.AddRow("Packet Metrics", "++++++++")
	resultsTable.AddSeparator()
	resultsTable.AddRow("Total pkts", totalPackets)
	resultsTable.AddRow("Avg pkt size", averagePacketSize)
	resultsTable.AddRow("Avg pkts/second", packetRate)
	resultsTable.AddRow("Total bytes", totalBytes)
	resultsTable.AddRow("Avg thoughput (Mbps)", float64(averageThrougput)*0.000008)
	resultsTable.AddSeparator()

	// Sort protocols
	var c []string
	for d := range etherType {
		c = append(c, d)
	}
	sort.Strings(c)

	// Create protocol table
	resultsTable.AddRow("Protocol Metrics", "++++++++")
	resultsTable.AddSeparator()
	resultsTable.AddRow("Ethernet", ethernetStats["count"])
	resultsTable.AddRow("TCP", tcpStats["count"])
	resultsTable.AddRow("UDP", udpStats["count"])
	resultsTable.AddRow("!Ethernet", ethernetStats["countErr"])
	for _, j := range c {
		resultsTable.AddRow(j, etherType[j])
	}
	resultsTable.AddSeparator()

	totalTCPConns := 0
	maxTCPConnsSec := 0

	for _, j := range newTCPConnectionsCreated {
		totalTCPConns += j
		if j > maxTCPConnsSec {
			maxTCPConnsSec = j
		}
	}

	tcpConnsPerSecond := totalTCPConns / totalTime

	totalUDPConns := 0
	maxUDPConnsSec := 0

	for _, j := range udpConnectionsStats {
		totalUDPConns += j
		if j > maxUDPConnsSec {
			maxUDPConnsSec = j
		}
	}

	udpConnsPerSecond := totalUDPConns / totalTime

	resultsTable.AddRow("Connections Metrics", "++++++++")
	resultsTable.AddSeparator()
	resultsTable.AddRow("TCP connections", totalTCPConns)
	resultsTable.AddRow("TCP conns/sec (avg) ", tcpConnsPerSecond)
	resultsTable.AddRow("TCP peak conns/sec", maxTCPConnsSec)
	resultsTable.AddRow("UDP connections", totalUDPConns)
	resultsTable.AddRow("UDP conns/sec (avg)", udpConnsPerSecond)
	resultsTable.AddRow("UDP peak conns/sec", maxUDPConnsSec)
	fmt.Println(resultsTable.Render())

	if *topN > 0 {
		connectionTable.topConnsByBytes(*topN)
		connectionTable.topSrc(*topN)
		connectionTable.topDst(*topN)
	}

	if *conntable == true {
		// Dump conn table
		connectionTable.dumpConnTable()
	}

	return
}

func (c connTable) topConnsByBytes(n int) {

	if len(c) < 1 {
		return
	}

	//Map for storing hash and conn bytes
	a := make(map[int]int)

	for b := range c {
		k := c[b][0].account.bytes
		a[b] = k
	}

	//Create kv struct pairs for sorting
	kvPair := make(intPairList, len(a))

	i := 0
	for k, v := range a {
		kvPair[i] = intPair{k, v}
		i++
	}
	sort.Sort(sort.Reverse(kvPair))

	if len(kvPair) < n {
		n = len(kvPair)
	}
	//Print table
	topConnsByBytesTable := termtables.CreateTable()
	topConnsByBytesTable.AddTitle("Top Connections by Bytes")
	topConnsByBytesTable.AddHeaders("Bytes", "Packets", "Source", "sPort", "Destination", "dPort", "Proto")
	for _, d := range kvPair[0 : n-1] {
		e := c[d.Key][0]
		topConnsByBytesTable.AddRow(e.account.bytes, e.account.packets, e.srcAddr, e.srcPort, e.dstAddr, e.dstPort, e.protocol)
	}
	fmt.Println(topConnsByBytesTable.Render())
}

func (c connTable) topSrc(n int) {

	if len(c) < 1 {
		return
	}

	//Map for storing hash and IPs
	a := make(map[string]int)

	for b := range c {
		k := c[b][0].srcAddr.String()
		a[k]++
	}

	//Create kv struct intPairs for sorting
	kvPair := make(stringPairList, len(a))

	i := 0
	for k, v := range a {
		kvPair[i] = stringPair{k, v}
		i++
	}
	sort.Sort(sort.Reverse(kvPair))

	//Print table
	topSrcIPTable := termtables.CreateTable()
	topSrcIPTable.AddTitle("Top Src IP Addresses")
	switch {
	case len(kvPair) > n:
		for _, d := range kvPair[:n-1] {
			topSrcIPTable.AddRow(d.Value, d.Key)
		}
	case len(kvPair) < n && len(kvPair) > 1:
		n = len(kvPair)
		for _, d := range kvPair[:n-1] {
			topSrcIPTable.AddRow(d.Value, d.Key)
		}
	case len(kvPair) == 1:
		for _, d := range kvPair {
			topSrcIPTable.AddRow(d.Value, d.Key)
		}
	default:
		fmt.Println("n: ", n)
		return
	}
	fmt.Println(topSrcIPTable.Render())
}

func (c connTable) topDst(n int) {

	if len(c) < 1 {
		return
	}

	//Map for storing hash and IPs
	a := make(map[string]int)

	for b := range c {
		k := c[b][0].dstAddr.String()
		a[k]++
	}

	//Create kv struct intPairs for sorting
	kvPair := make(stringPairList, len(a))

	i := 0
	for k, v := range a {
		kvPair[i] = stringPair{k, v}
		i++
	}
	sort.Sort(sort.Reverse(kvPair))

	//Print table
	topDstIPTable := termtables.CreateTable()
	topDstIPTable.AddTitle("Top Dst IP Addresses")
	switch {
	case len(kvPair) > n:
		for _, d := range kvPair[:n-1] {
			topDstIPTable.AddRow(d.Value, d.Key)
		}
	case len(kvPair) < n && len(kvPair) > 1:
		n = len(kvPair)
		for _, d := range kvPair[:n-1] {
			topDstIPTable.AddRow(d.Value, d.Key)
		}
	case len(kvPair) == 1:

		for _, d := range kvPair {
			topDstIPTable.AddRow(d.Value, d.Key)
		}
	default:
		return
	}
	fmt.Println(topDstIPTable.Render())
}

func (p intPairList) Len() int           { return len(p) }
func (p intPairList) Less(i, j int) bool { return p[i].Value < p[j].Value }
func (p intPairList) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }

func (p stringPairList) Len() int           { return len(p) }
func (p stringPairList) Less(i, j int) bool { return p[i].Value < p[j].Value }
func (p stringPairList) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
