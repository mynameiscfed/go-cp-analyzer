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
	"sort"
)

var (
	pFile               = flag.String("r", "", "pcap file name")
	conntable           = flag.Bool("with-conntable", false, "dump connections table")
	err                 error
	handle              *pcap.Handle
	totalBytes          = 0
	packetLengthStats   = make(map[int]int)
	ppsStats            = make(map[int64]int)
	ethernetStats       = make(map[string]int)
	etherType           = make(map[string]int)
	tcpStats            = make(map[string]int)
	udpStats            = make(map[string]int)
	connectionTable     = make(map[uint64][]connection)
	tcpConnectionsStats = make(map[int64]int)
	udpConnectionsStats = make(map[int64]int)
	eth                 layers.Ethernet

//	ip4                 layers.IPv4
//	ip6                 layers.IPv6
//	tcp                 layers.TCP
//	udp                 layers.UDP
)

// connection is a struct that holds IP connection information

type connection struct {
	srcAddr   net.IP
	dstAddr   net.IP
	srcPort   uint16
	dstPort   uint16
	protocol  uint8
	connState uint8
}

type tcpState struct {
	SYN bool
	ACK bool
	PSH bool
	FIN bool
	RST bool
}

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

func processPacket(packet gopacket.Packet) {

	// Get the packet length and count it. Must use Metadata and not
	// the data length to support when full packet was not captured.
	packetLength := packet.Metadata().Length
	totalBytes += packetLength
	packetTime := packet.Metadata().Timestamp.Unix()
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
		ethernetPacket := eth
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

	// Get application layer info

	// Check if this is a new TCP C->S connection or and established connection
	if ipProto == 6 {
		isConn, hash, _ := connectionLoookup(srcIP, dstIP, srcPort, dstPort, ipProto)
		if isConn == true {
			s := checkTCPState(state)
			connectionTable[hash][0].connState = s
		} else {
			// Establish a new TCP connection
			hash = connectionHash(srcIP, dstIP, srcPort, dstPort, ipProto)
			s := checkTCPState(state)
			if s == 1 {
				conn := connection{srcIP, dstIP, srcPort, dstPort, ipProto, s}
				connectionTable[hash] = append(connectionTable[hash], conn)
				// Update tcp connection stats for CPS count
				tcpConnectionsStats[packetTime]++
			} else {
				// No connection found. Most likely pcap started while connection was in progress.
			}
		}
		return
	}

	// Check if this is a new UDP C->S connection or and established connection
	// In a firewall the conn will be deleted after N seconds of the last packet.
	if ipProto == 17 {
		isConn, hash, cs := connectionLoookup(srcIP, dstIP, srcPort, dstPort, ipProto)
		if isConn == true {
			if cs == 1 {
				connectionTable[hash][0].connState = cs
			} else if cs == 2 {
				connectionTable[hash][0].connState = cs
			}
		} else {
			// Establish a new UDP connection
			hash = connectionHash(srcIP, dstIP, srcPort, dstPort, ipProto)
			conn := connection{srcIP, dstIP, srcPort, dstPort, ipProto, 1}
			connectionTable[hash] = append(connectionTable[hash], conn)
			udpConnectionsStats[packetTime]++
		}
		return
	}

}

// Prints the final results
func printResults() {

	// Sort packetLengthStats
	var a []int
	for b := range packetLengthStats {
		a = append(a, b)
	}
	sort.Ints(a)

	// Create packetLengthStats table
	packetLengthTable := termtables.CreateTable()
	packetLengthTable.Style.PaddingRight = 5
	packetLengthTable.Style.PaddingLeft = 5
	packetLengthTable.AddTitle("Packet Size Distribution")
	packetLengthTable.AddHeaders("Size", "Count")
	for _, i := range a {
		b := fmt.Sprintf(" <= %d", i)
		packetLengthTable.AddRow(b, packetLengthStats[i])
	}
	fmt.Println(packetLengthTable.Render())

	totalPackets := int64(0)
	for _, j := range ppsStats {
		totalPackets += int64(j)
	}
	packetRate := totalPackets / int64(len(ppsStats)-1)
	averagePacketSize := int64(totalBytes) / totalPackets

	// Create packet stats table
	packetStatsTable := termtables.CreateTable()
	packetStatsTable.Style.PaddingRight = 5
	packetStatsTable.Style.PaddingLeft = 5
	packetStatsTable.AddTitle("Packet Metrics")
	packetStatsTable.AddRow("Total pkts", totalPackets)
	packetStatsTable.AddRow("Average pkt size", averagePacketSize)
	packetStatsTable.AddRow("Average pkts/second", packetRate)
	packetStatsTable.AddRow("Total bytes", totalBytes)
	fmt.Println(packetStatsTable.Render())

	// Sort protocols
	var c []string
	for d := range etherType {
		c = append(c, d)
	}
	sort.Strings(c)

	// Create protocol table
	protocolStatsTable := termtables.CreateTable()
	protocolStatsTable.Style.PaddingRight = 5
	protocolStatsTable.Style.PaddingLeft = 5
	protocolStatsTable.AddTitle("Protocol Metrics")
	protocolStatsTable.AddHeaders("Protocol", "Count")
	protocolStatsTable.AddRow("Ethernet", ethernetStats["count"])
	protocolStatsTable.AddRow("TCP", tcpStats["count"])
	protocolStatsTable.AddRow("UDP", udpStats["count"])
	protocolStatsTable.AddRow("!Ethernet", ethernetStats["countErr"])
	protocolStatsTable.AddSeparator()
	for _, j := range c {
		protocolStatsTable.AddRow(j, etherType[j])
	}
	fmt.Println(protocolStatsTable.Render())

	totalTCPConns := int64(0)

	for _, j := range tcpConnectionsStats {
		totalTCPConns += int64(j)
	}

	tcpConnsPerSecond := totalTCPConns / int64(len(ppsStats))

	totalUDPConns := int64(0)
	for _, j := range udpConnectionsStats {
		totalUDPConns += int64(j)
	}

	udpConnsPerSecond := totalUDPConns / int64(len(ppsStats))

	connectionStatsTable := termtables.CreateTable()
	connectionStatsTable.Style.PaddingRight = 5
	connectionStatsTable.Style.PaddingLeft = 5
	connectionStatsTable.AddTitle("Connections Metrics")
	connectionStatsTable.AddRow("TCP connections", totalTCPConns)
	connectionStatsTable.AddRow("TCP conns/second", tcpConnsPerSecond)
	connectionStatsTable.AddSeparator()
	connectionStatsTable.AddRow("UDP connections", totalUDPConns)
	connectionStatsTable.AddRow("UDP conns/second", udpConnsPerSecond)
	fmt.Println(connectionStatsTable.Render())

	if *conntable == true {
		// Dump conn table
		cT := termtables.CreateTable()
		cT.AddTitle("Connections Table")
		cT.Style.PaddingLeft = 1
		cT.Style.PaddingRight = 1
		for i := range connectionTable {
			cT.AddRow(i, connectionTable[i][0].srcAddr, connectionTable[i][0].srcPort, connectionTable[i][0].dstAddr, connectionTable[i][0].dstPort, connectionTable[i][0].protocol)
			cT.AddSeparator()
		}
		fmt.Println(cT.Render())
	}
	return
}

// Creates 5-tuple hash
func connectionHash(srcIP net.IP, dstIP net.IP, srcPort uint16, dstPort uint16, ipProto uint8) uint64 {

	hash := uint(ipProto)
	hashBits := uint(20)

	a := ipToInt(srcIP)
	b := ipToInt(dstIP)
	c := uint(srcPort)
	d := uint(dstPort)

	for idx := uint(0); idx < 32; idx += hashBits {
		hash += (a * 59 >> (uint(32) - idx)) + (b * 59 >> idx) + (c * 59) + (d * 59)
	}

	return uint64(hash)

}

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

func connectionLoookup(srcIP net.IP, dstIP net.IP, srcPort uint16, dstPort uint16, ipProto uint8) (bool, uint64, uint8) {

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
// 3 C->S established
// 4 FIN/RST - close conn
// 5 no match - in a connection
func checkTCPState(t tcpState) uint8 {
	if t.SYN == true && t.ACK == false && t.RST == false && t.FIN == false && t.PSH == false {
		return 1
	} else if t.SYN == true && t.ACK == true && t.RST == false && t.FIN == false && t.PSH == false {
		return 2
	} else if t.SYN == false && t.ACK == true && t.RST == false && t.FIN == false && t.PSH == false {
		return 3
	} else if t.FIN == true || t.RST == true {
		return 4
	} else {
		return 5
	}
}
