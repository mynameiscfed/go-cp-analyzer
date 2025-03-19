package main

import (
	"flag"
	"log"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var (
	pFile                    = flag.String("r", "", "pcap `file name` ")
	htmlOut                  = flag.String("html-out", "", "output HTML report to `file`")
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

	// If HTML output is requested, generate it and exit
	if *htmlOut != "" {
		if err := generateHTMLReport(*htmlOut); err != nil {
			log.Fatal(err)
		}
		return
	}

	// Initialize and run the UI
	p := tea.NewProgram(initialModel())
	if _, err := p.Run(); err != nil {
		log.Fatal(err)
	}
}
