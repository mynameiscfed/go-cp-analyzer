package main

import (
	"flag"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var (
	pFile                    = flag.String("r", "", "pcap `file name` ")
	conntable                = flag.Bool("c", false, "dump connections table")
	topN                     = flag.Int("n", 0, "top N connections")
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
