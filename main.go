package main

import (
	"flag"
	"fmt"
	"github.com/apcera/termtables"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"os"
	"sort"
	"text/tabwriter"
)

var (
	pFile                    = flag.String("r", "", "pcap file name")
	conntable                = flag.Bool("c", false, "dump connections table")
	topN                     = flag.Int("n", 0, "top N connetions")
	err                      error
	handle                   *pcap.Handle
	totalBytes               = 0
	packetLengthStats        = make(map[int]int)
	ppsStats                 = make(map[int]int)
	ethernetStats            = make(map[string]int)
	etherType                = make(map[string]int)
	tcpStats                 = make(map[string]int)
	udpStats                 = make(map[string]int)
	connectionTable          = make(connTable)
	newTCPConnectionsCreated = make(map[int]int)
	udpConnectionsStats      = make(map[int]int)
)

// connection is a struct that holds IP connection information

type connTable map[int][]connection

type connection struct {
	srcAddr   net.IP
	dstAddr   net.IP
	srcPort   uint16
	dstPort   uint16
	protocol  uint8
	connState uint8
	acctBytes int
}

type tcpState struct {
	SYN bool
	ACK bool
	PSH bool
	FIN bool
	RST bool
}

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

func main() {

	// Parse flags
	flag.Parse()
	// Open device
	handle, err = pcap.OpenOffline(*pFile)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Process packet here
		processPacket(packet)
	}

	printResults()
}

// processPacket decodes each defined layer and collects important data
func processPacket(packet gopacket.Packet) {

	// Get the packet length and count it. Must use Metadata and not
	// the data length to support when full packet was not captured.
	packetLength := packet.Metadata().Length
	totalBytes += packetLength
	packetTime := int(packet.Metadata().Timestamp.Unix())
	ppsStats[packetTime]++

	switch {
	case packetLength <= 66:
		packetLengthStats[66]++
	case packetLength <= 128:
		packetLengthStats[128]++
	case packetLength <= 256:
		packetLengthStats[256]++
	case packetLength <= 384:
		packetLengthStats[384]++
	case packetLength <= 512:
		packetLengthStats[512]++
	case packetLength <= 768:
		packetLengthStats[768]++
	case packetLength <= 1024:
		packetLengthStats[1024]++
	case packetLength <= 1518:
		packetLengthStats[1518]++
	case packetLength > 1518:
		packetLengthStats[9000]++
	}

	// Get the Ethernet stats
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		a := fmt.Sprintf(ethernetPacket.EthernetType.String())
		etherType[a]++
		ethernetStats["count"]++
	} else {
		ethernetStats["countErr"]++
	}

	// Define 5-tuple vars and state struct
	var srcIP, dstIP net.IP
	var srcPort, dstPort uint16
	var ipProto uint8
	var state tcpState

	// Get IPv4 info
	ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ipv4Layer != nil {
		ipv4Packet, _ := ipv4Layer.(*layers.IPv4)
		srcIP = ipv4Packet.SrcIP
		dstIP = ipv4Packet.DstIP
		ipProto = uint8(ipv4Packet.Protocol)
	}

	// Get IPv6 info
	ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
	if ipv6Layer != nil {
		ipv6Packet, _ := ipv6Layer.(*layers.IPv6)
		srcIP = ipv6Packet.SrcIP
		dstIP = ipv6Packet.DstIP
		ipProto = uint8(ipv6Packet.NextHeader)
	}

	// Get TCP info
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcpStats["count"]++
		tcpPacket, _ := tcpLayer.(*layers.TCP)
		srcPort = uint16(tcpPacket.SrcPort)
		dstPort = uint16(tcpPacket.DstPort)
		state = tcpState{tcpPacket.SYN, tcpPacket.ACK, tcpPacket.PSH, tcpPacket.FIN, tcpPacket.RST}
	}

	// Get UDP info
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		udpStats["count"]++
		udpPacket, _ := udpLayer.(*layers.UDP)
		srcPort = uint16(udpPacket.SrcPort)
		dstPort = uint16(udpPacket.DstPort)
	}

	// Check if this is a new TCP C->S connection or and established connection
	switch {

	case ipProto == 6:
		isConn, hash, _ := connectionLoookup(srcIP, dstIP, srcPort, dstPort, ipProto)
		if isConn == true {
			s := checkTCPState(state)
			connectionTable[hash][0].connState = s
			connectionTable[hash][0].acctBytes += packetLength
		} else {
			// Establish a new TCP connection
			hash = connectionHash(srcIP, dstIP, srcPort, dstPort, ipProto)
			s := checkTCPState(state)
			if s == 1 {
				conn := connection{srcIP, dstIP, srcPort, dstPort, ipProto, s, packetLength}
				connectionTable[hash] = append(connectionTable[hash], conn)
				// Update tcp connection stats for CPS count
				newTCPConnectionsCreated[packetTime]++
			} else {
				// No connection found. Most likely pcap started while connection was in progress.
			}
		}
		return

	// Check if this is a new UDP C->S connection or and established connection
	// In a firewall the conn will be deleted after N seconds of the last packet.
	case ipProto == 17:
		isConn, hash, cs := connectionLoookup(srcIP, dstIP, srcPort, dstPort, ipProto)
		if isConn == true {
			if cs == 1 {
				connectionTable[hash][0].connState = cs
				connectionTable[hash][0].acctBytes += packetLength
			} else if cs == 2 {
				connectionTable[hash][0].connState = cs
				connectionTable[hash][0].acctBytes += packetLength
			}
		} else {
			// Establish a new UDP connection
			hash = connectionHash(srcIP, dstIP, srcPort, dstPort, ipProto)
			conn := connection{srcIP, dstIP, srcPort, dstPort, ipProto, 1, packetLength}
			connectionTable[hash] = append(connectionTable[hash], conn)
			udpConnectionsStats[packetTime]++
		}
		return

	}
}

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

//connectionHash creates 5-tuple hash used for the hash map connectionTable
func connectionHash(srcIP net.IP, dstIP net.IP, srcPort uint16, dstPort uint16, ipProto uint8) int {

	hash := uint(ipProto)
	hashBits := uint(20)

	a := ipToInt(srcIP)
	b := ipToInt(dstIP)
	c := uint(srcPort)
	d := uint(dstPort)

	for idx := uint(0); idx < 32; idx += hashBits {
		hash += (a * 59 >> (uint(32) - idx)) + (b * 59 >> idx) + (c * 59) + (d * 59)
	}

	return int(hash)

}

//ipToInt takes an IP address and returns it as an int.
//IPv6 addresses return the last 4 bytes only.
func ipToInt(ip net.IP) uint {

	// Take the last 4 bytes. If IPv4 this is all the bytes. If IPv6 this is the last 4 bytes
	b := ip[len(ip)-4:]

	// Little endian - TODO big endian
	b0 := uint(b[0]) << 24
	b1 := uint(b[1]) << 16
	b2 := uint(b[2]) << 8
	b3 := uint(b[3])

	return b0 + b1 + b2 + b3
}

//connectionLoookup searches hash map connectionTable to see if a connection is already established
func connectionLoookup(srcIP net.IP, dstIP net.IP, srcPort uint16, dstPort uint16, ipProto uint8) (bool, int, uint8) {

	a := connectionHash(srcIP, dstIP, srcPort, dstPort, ipProto)
	b := connectionHash(dstIP, srcIP, dstPort, srcPort, ipProto)
	if _, ok := connectionTable[a]; ok {
		return true, a, 1
	} else if _, ok := connectionTable[b]; ok {
		return true, b, 2
	}
	return false, 0, 0
}

// checkTcpState returns the state of a connection
// 1 C->S connection
// 2 S->C reply
// 3 C->S established / ACK only
// 4 FIN/RST - close conn
// 5 no match - in a connection
func checkTCPState(t tcpState) uint8 {
	switch {
	case t.SYN == true && t.ACK == false && t.RST == false && t.FIN == false && t.PSH == false:
		return 1
	case t.SYN == true && t.ACK == true && t.RST == false && t.FIN == false && t.PSH == false:
		return 2
	case t.SYN == false && t.ACK == true && t.RST == false && t.FIN == false && t.PSH == false:
		return 3
	case t.FIN == true || t.RST == true:
		return 4
	default:
		return 5
	}
}

//dumpConnTable prints out the contents of a connection table
func (c connTable) dumpConnTable() {
	a := "+------------------------------------+"
	b := "+---+"
	w := new(tabwriter.Writer)
	w.Init(os.Stdout, 0, 8, 0, '\t', 0)
	fmt.Fprintln(w, "src", "\t", "sport", "\t", "dst", "\t", "dport", "\t", "proto", "\t", "bytes")
	for i := range c {
		fmt.Fprintln(w, a, "\t", b, "\t", a, "\t", b, "\t", b, "\t", b)
		fmt.Fprintln(w, c[i][0].srcAddr, "\t", c[i][0].srcPort, "\t", c[i][0].dstAddr, "\t", c[i][0].dstPort, "\t", c[i][0].protocol, "\t", c[i][0].acctBytes)
	}
	w.Flush()

}

func (c connTable) topConnsByBytes(n int) {

	if len(c) < 1 {
		return
	}

	//Map for storing hash and conn bytes
	a := make(map[int]int)

	for b := range c {
		k := c[b][0].acctBytes
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
	topConnsByBytesTable.AddHeaders("Bytes", "Src", "SrcPort", "Dst", "DstPort", "Proto")
	for _, d := range kvPair[0 : n-1] {
		e := c[d.Key][0]
		topConnsByBytesTable.AddRow(e.acctBytes, e.srcAddr, e.srcPort, e.dstAddr, e.dstPort, e.protocol)
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
	topSrcIPTable.AddTitle("Top Dst IP Addresses")
	switch {
    case len(kvPair) > n :
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
    case len(kvPair) > n :
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
