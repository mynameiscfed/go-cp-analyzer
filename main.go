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
	pFile             = flag.String("r", "", "pcap file name")
	err               error
	handle            *pcap.Handle
	eth               layers.Ethernet
	ip4               layers.IPv4
	ip6               layers.IPv6
	tcp               layers.TCP
	parser            = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp)
	decoded           = []gopacket.LayerType{}
	packetLengthStats = make(map[string]int)
	ppsStats          = make(map[int64]int)
	ethernetStats     = make(map[string]int)
	etherType         = make(map[string]int)
	tcpStats          = make(map[string]int)
	udpStats          = make(map[string]int)
	connectionTable   = make(map[int64]connection)
)

type connection struct {
	srcAddr  net.IP
	dstAddr  net.IP
	srcPort  uint16
	dstPort  uint16
	protocol uint8
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

	var srcIP, dstIP net.IP
	var srcPort, dstPort uint16
	var ipProto uint8

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
	}

	// Get UDP stats
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		udpStats["count"]++
		udpPacket, _ := udpLayer.(*layers.UDP)
		srcPort = uint16(udpPacket.SrcPort)
		dstPort = uint16(udpPacket.DstPort)
	}

	// Try to create a connection
	myConn := connection{srcIP, dstIP, srcPort, dstPort, ipProto}
	fmt.Println(myConn)
	return
}

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

	sum := int64(0)
	for _, j := range ppsStats {
		sum += int64(j)
	}
	packetRate := sum / int64(len(ppsStats)-1)
	fmt.Println("Average PPS: ", packetRate)
	return
}
