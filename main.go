package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
)

var (
	pFile  = flag.String("r", "", "pcap file name")
	err    error
	handle *pcap.Handle
	eth    layers.Ethernet
	ip4    layers.IPv4
	ip6    layers.IPv6
	tcp    layers.TCP
	parser = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp)
	//decoded           = []gopacket.LayerType{}
	packetLengthStats = make(map[string]int)
	ppsStats          = make(map[int64]int)
	ethernetStats     = make(map[string]int)
	etherType         = make(map[string]int)
	tcpStats          = make(map[string]int)
	udpStats          = make(map[string]int)
	connectionTable   = make(map[uint64][]connection)
	connetionStats    = make(map[int64]int)
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
		getPacketInfo(packet)
	}
	printResults()
}

func getPacketInfo(packet gopacket.Packet) {

	// Get the packet length and count it. Must use Metadata and not
	// the data length to support when full packet was not captured.

	packetLength := packet.Metadata().Length
	packetTime := packet.Metadata().Timestamp.Unix()
	ppsStats[packetTime]++

	switch {
	case packetLength <= 66:
		packetLengthStats["66"]++
	case packetLength <= 128:
		packetLengthStats["128"]++
	case packetLength <= 256:
		packetLengthStats["256"]++
	case packetLength <= 384:
		packetLengthStats["384"]++
	case packetLength <= 512:
		packetLengthStats["512"]++
	case packetLength <= 768:
		packetLengthStats["768"]++
	case packetLength <= 1024:
		packetLengthStats["1024"]++
	case packetLength <= 1518:
		packetLengthStats["1518"]++
	case packetLength > 1518:
		packetLengthStats["jumbo"]++
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

	// Define our 5-tuple vars
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

	// Get TCP stats
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcpStats["count"]++
		tcpPacket, _ := tcpLayer.(*layers.TCP)
		srcPort = uint16(tcpPacket.SrcPort)
		dstPort = uint16(tcpPacket.DstPort)
		state = tcpState{tcpPacket.SYN, tcpPacket.ACK, tcpPacket.PSH, tcpPacket.FIN, tcpPacket.RST}
	}

	// Get UDP stats
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		udpStats["count"]++
		udpPacket, _ := udpLayer.(*layers.UDP)
		srcPort = uint16(udpPacket.SrcPort)
		dstPort = uint16(udpPacket.DstPort)
	}

	// Check if this is a new TCP C->S connection or and established connection
	if ipProto == 6 {
		isConn, hash, cs := connectionLoookup(srcIP, dstIP, srcPort, dstPort, ipProto)
		if isConn == true {
			s := checkTcpState(state)
			connectionTable[hash][0].connState = s
			if cs == 1 {
				// TODO
			} else if cs == 2 {
				// TODO
			}
		} else {
			// Establish a new TCP connection
			hash = connectionHash(srcIP, dstIP, srcPort, dstPort, ipProto)
			conn := connection{srcIP, dstIP, srcPort, dstPort, ipProto, 1}
			s := checkTcpState(state)
			if s == 1 {
				connectionTable[hash] = append(connectionTable[hash], conn)
				// Update tcp connection stats for CPS count
				connetionStats[packetTime]++
			} else {
				//Discard it. It is out of state. New TCP connections should only have SYN set.
			}
		}
		return
	}
}

// Prints the final results
func printResults() {

	fmt.Println("Packet Size Distribution")
	fmt.Println(" <=    66: ", packetLengthStats["66"])
	fmt.Println(" <=   128: ", packetLengthStats["128"])
	fmt.Println(" <=   256: ", packetLengthStats["256"])
	fmt.Println(" <=   384: ", packetLengthStats["384"])
	fmt.Println(" <=   512: ", packetLengthStats["512"])
	fmt.Println(" <=   768: ", packetLengthStats["768"])
	fmt.Println(" <=  1024: ", packetLengthStats["1024"])
	fmt.Println(" <=  1518: ", packetLengthStats["1518"])
	fmt.Println("    jumbo: ", packetLengthStats["jumbo"])
	fmt.Println("Ethernet packets: ", ethernetStats["count"])
	for i, j := range etherType {
		fmt.Println("    ", i, ": \t", j)
	}
	fmt.Println("TCP packets: ", tcpStats["count"])
	fmt.Println("UDP packets: ", udpStats["count"])
	fmt.Println("Non-ethernet packets: ", ethernetStats["countErr"])

	totalPackets := int64(0)

	for _, j := range ppsStats {
		totalPackets += int64(j)
	}
	packetRate := totalPackets / int64(len(ppsStats)-1)
	fmt.Println("Average PPS: ", packetRate)

	totalTcpConns := int64(0)
	for _, j := range connetionStats {
		totalTcpConns += int64(j)
	}
	tcpConnsPerSecond := totalTcpConns / int64(len(ppsStats))
	fmt.Println("Average TCP conns per sec: ", tcpConnsPerSecond)
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
		hash += (a*59>>uint(32) - idx) + (b * 59 >> idx) + (c * 59) + (d * 59)
	}

	return uint64(hash)

}

func ipToInt(ip net.IP) uint {

	// Take the last 4 bytes. If IPv4 this is all the bytes. If IPv6 this is the last 4 bytes
	b := ip[len(ip)-4 : len(ip)]

	// Little endian
	b0 := uint(b[0]) << 24
	b1 := uint(b[1]) << 16
	b2 := uint(b[2]) << 8
	b3 := uint(b[3])

	return b0 + b1 + b2 + b3
}

func connectionLoookup(srcIP net.IP, dstIP net.IP, srcPort uint16, dstPort uint16, ipProto uint8) (bool, uint64, int) {

	a := connectionHash(srcIP, dstIP, srcPort, dstPort, ipProto)
	b := connectionHash(dstIP, srcIP, dstPort, srcPort, ipProto)
	if connectionTable[a] != nil {
		return true, a, 1
	} else if connectionTable[b] != nil {
		return true, b, 2
	}
	return false, 0, 0
}

// checkTcpState returns the state of a connection
// 1 C->S connection
// 2 S->C reply
// 3 C->S established
// 4 FIN/RST - close conn
// 5 no match
func checkTcpState(t tcpState) uint8 {
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
