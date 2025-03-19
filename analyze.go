package main

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

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
		ethernetPacket, ok := ethernetLayer.(*layers.Ethernet)
		if !ok {
			ethernetStats["countErr"]++
			return
		}
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
		ipv4Packet, ok := ipv4Layer.(*layers.IPv4)
		if !ok {
			return
		}
		srcIP = ipv4Packet.SrcIP
		dstIP = ipv4Packet.DstIP
		ipProto = uint8(ipv4Packet.Protocol)
	}

	// Get IPv6 info
	ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
	if ipv6Layer != nil {
		ipv6Packet, ok := ipv6Layer.(*layers.IPv6)
		if !ok {
			return
		}
		srcIP = ipv6Packet.SrcIP
		dstIP = ipv6Packet.DstIP
		ipProto = uint8(ipv6Packet.NextHeader)
	}

	// Skip if we don't have IP information
	if srcIP == nil || dstIP == nil {
		return
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
		isConn, hash, _ := connectionLookup(srcIP, dstIP, srcPort, dstPort, ipProto)
		if isConn == true {
			s := checkTCPState(state)
			connectionTable[hash][0].connState = s
			connectionTable[hash][0].account.bytes += packetLength
			connectionTable[hash][0].account.packets++
		} else {
			// Establish a new TCP connection
			hash = connectionHash(srcIP, dstIP, srcPort, dstPort, ipProto)
			s := checkTCPState(state)
			if s == 1 {
				conn := connection{srcIP, dstIP, srcPort, dstPort, ipProto, s, accounting{packetLength, 1}}
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
		isConn, hash, _ := connectionLookup(srcIP, dstIP, srcPort, dstPort, ipProto)
		if isConn == true {
			// For UDP, we just update the accounting info
			connectionTable[hash][0].account.bytes += packetLength
			connectionTable[hash][0].account.packets++
		} else {
			// Establish a new UDP connection
			hash = connectionHash(srcIP, dstIP, srcPort, dstPort, ipProto)
			// UDP connections are always in state 1 (established)
			conn := connection{srcIP, dstIP, srcPort, dstPort, ipProto, 1, accounting{packetLength, 1}}
			connectionTable[hash] = append(connectionTable[hash], conn)
			udpConnectionsStats[packetTime]++
		}
		return

	}
}
