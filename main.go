package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
)

var (
	pFile         = flag.String("r", "", "device name")
	err           error
	handle        *pcap.Handle
	eth           layers.Ethernet
	ip4           layers.IPv4
	ip6           layers.IPv6
	tcp           layers.TCP
	parser        = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp)
	decoded       = []gopacket.LayerType{}
	packetLen     = make(map[string]int)
	ethernetStats = make(map[string]int)
)

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
	// Get the packet length and count it.
	b := packet.Data()
	pkLen := len(b)
	switch {
	case pkLen <= 66:
		packetLen["66"]++
	case pkLen <= 128:
		packetLen["128"]++
	case pkLen <= 256:
		packetLen["256"]++
	case pkLen <= 384:
		packetLen["384"]++
	case pkLen <= 512:
		packetLen["512"]++
	case pkLen <= 768:
		packetLen["768"]++
	case pkLen <= 1024:
		packetLen["1024"]++
	case pkLen <= 1518:
		packetLen["1518"]++
	}

	// Get the Ethernet  stats and count them
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		fmt.Println("Ethernet type: ", ethernetPacket.EthernetType)
		ethernetStats["count"]++
	} else {
		ethernetStats["countErr"]++
	}
	return
}

func printResults() {

	fmt.Println("  <=66: ", packetLen["66"])
	fmt.Println(" <=128: ", packetLen["128"])
	fmt.Println(" <=256: ", packetLen["256"])
	fmt.Println(" <=384: ", packetLen["384"])
	fmt.Println(" <=512: ", packetLen["512"])
	fmt.Println(" <=768: ", packetLen["768"])
	fmt.Println("<=1024: ", packetLen["1024"])
	fmt.Println("<=1518: ", packetLen["1518"])

	fmt.Println("Ethernet packets: ", ethernetStats["count"])
	fmt.Println("Non-ethernet p ackets: ", ethernetStats["countErr"])

	return
}
