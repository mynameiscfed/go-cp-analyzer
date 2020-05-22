package main

import (
	"fmt"
	"os"
	"sort"
	"strconv"

	"github.com/olekukonko/tablewriter"
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

const COLUMN_HEADER = ""

func newFormattedTableWriter() *tablewriter.Table {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetColMinWidth(0, 30)
	table.SetColMinWidth(1, 20)
	table.SetAutoFormatHeaders(false)
	table.SetTablePadding("\t")
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	return table
}

//printResults prints the final results
func printResults() {
	var table *tablewriter.Table

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

	table = newFormattedTableWriter()
	table.SetHeader([]string{"Packet Distribution", COLUMN_HEADER})
	for _, i := range a {
		b := fmt.Sprintf(" <= %d", i)
		table.Append([]string{b, strconv.Itoa(packetLengthStats[i])})
	}
	table.Render()

	totalPackets := 0

	for _, j := range ppsStats {
		totalPackets += j
	}

	packetRate := totalPackets / totalTime
	averagePacketSize := totalBytes / totalPackets
	averageThrougput := totalBytes / totalTime

	table = newFormattedTableWriter()
	table.SetHeader([]string{"Packet Metrics", COLUMN_HEADER})
	table.Append([]string{"Total pkts", strconv.Itoa(totalPackets)})
	table.Append([]string{"Avg pkt size", strconv.Itoa(averagePacketSize)})
	table.Append([]string{"Avg pkts/second", strconv.Itoa(packetRate)})
	table.Append([]string{"Avg thoughput (Mbps)", strconv.FormatFloat(float64(averageThrougput)*0.000008, 'f', 2, 64)})
	table.Render()

	// Sort protocols
	var c []string
	for d := range etherType {
		c = append(c, d)
	}
	sort.Strings(c)

	// Create protocol table
	table = newFormattedTableWriter()
	table.SetHeader([]string{"Protocol Metrics", COLUMN_HEADER})
	table.Append([]string{"Ethernet", strconv.Itoa(ethernetStats["count"])})
	table.Append([]string{"TCP", strconv.Itoa(tcpStats["count"])})
	table.Append([]string{"UDP", strconv.Itoa(udpStats["count"])})
	table.Append([]string{"!Ethernet", strconv.Itoa(ethernetStats["countErr"])})

	for _, j := range c {
		table.Append([]string{j, strconv.Itoa(etherType[j])})
	}
	table.Render()

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

	table = newFormattedTableWriter()
	table.SetHeader([]string{"Connections Metrics", COLUMN_HEADER})
	table.Append([]string{"TCP connections", strconv.Itoa(totalTCPConns)})
	table.Append([]string{"TCP conns/sec (avg)", strconv.Itoa(tcpConnsPerSecond)})
	table.Append([]string{"TCP peak conns/sec", strconv.Itoa(maxTCPConnsSec)})
	table.Append([]string{"UDP connections", strconv.Itoa(totalUDPConns)})
	table.Append([]string{"UDP conns/sec (avg)", strconv.Itoa(udpConnsPerSecond)})
	table.Append([]string{"UDP peak conns/sec", strconv.Itoa(maxUDPConnsSec)})
	table.Render()

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
	var table *tablewriter.Table

	fmt.Println("Top Connections by Bytes")
	table = newFormattedTableWriter()
	table.SetHeader([]string{"Bytes", "Packets", "Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol"})
	for _, d := range kvPair[0 : n-1] {
		e := c[d.Key][0]
		table.Append([]string{strconv.Itoa(e.account.bytes), strconv.Itoa(e.account.packets), e.srcAddr.String(), strconv.Itoa(int(e.srcPort)), e.dstAddr.String(), strconv.Itoa(int(e.dstPort)), strconv.Itoa(int(e.protocol))})

	}
	table.Render()
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
	var table *tablewriter.Table

	fmt.Println("Top Source IP Addresses")
	table = newFormattedTableWriter()
	table.SetHeader([]string{"Hits", "IP Address"})
	switch {
	case len(kvPair) > n:
		for _, d := range kvPair[:n-1] {
			table.Append([]string{strconv.Itoa(d.Value), d.Key})
		}
	case len(kvPair) < n && len(kvPair) > 1:
		n = len(kvPair)
		for _, d := range kvPair[:n-1] {
			table.Append([]string{strconv.Itoa(d.Value), d.Key})
		}
	case len(kvPair) == 1:
		for _, d := range kvPair {
			table.Append([]string{strconv.Itoa(d.Value), d.Key})
		}
	default:
		fmt.Println("n: ", n)
		return
	}
	table.Render()
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
	var table *tablewriter.Table

	fmt.Println("Top Destination IP Addresses")
	table = newFormattedTableWriter()
	table.SetHeader([]string{"Hits", "IP Address"})
	switch {
	case len(kvPair) > n:
		for _, d := range kvPair[:n-1] {
			table.Append([]string{strconv.Itoa(d.Value), d.Key})
		}
	case len(kvPair) < n && len(kvPair) > 1:
		n = len(kvPair)
		for _, d := range kvPair[:n-1] {
			table.Append([]string{strconv.Itoa(d.Value), d.Key})
		}
	case len(kvPair) == 1:

		for _, d := range kvPair {
			table.Append([]string{strconv.Itoa(d.Value), d.Key})
		}
	default:
		return
	}
	table.Render()
}

func (p intPairList) Len() int           { return len(p) }
func (p intPairList) Less(i, j int) bool { return p[i].Value < p[j].Value }
func (p intPairList) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }

func (p stringPairList) Len() int           { return len(p) }
func (p stringPairList) Less(i, j int) bool { return p[i].Value < p[j].Value }
func (p stringPairList) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
