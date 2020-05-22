package main

import (
	"fmt"
	"net"
	"strconv"

	"github.com/olekukonko/tablewriter"
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
	account   accounting
}

type accounting struct {
	bytes   int
	packets int
}

type tcpState struct {
	SYN bool
	ACK bool
	PSH bool
	FIN bool
	RST bool
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
		hash += (a * 17 >> (uint(32) - idx)) + (b * 17 >> idx) + (c * 17) + (d * 17)
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
	} else {
		return false, 0, 0
	}
}

// checkTcpState returns the simple TCP state of a connection
// 1 C->S connection
// 2 S->C reply
// 3 C->S established / ACK only
// 4 FIN/RST - close conn
// 5 no match - in a connection
func checkTCPState(t tcpState) uint8 {
	switch {
	// SYN sent state
	case t.SYN == true && t.ACK == false && t.RST == false && t.FIN == false && t.PSH == false:
		return 1
	// SYN received state
	case t.SYN == true && t.ACK == true && t.RST == false && t.FIN == false && t.PSH == false:
		return 2
	// EST state
	case t.SYN == false && t.ACK == true && t.RST == false && t.FIN == false && t.PSH == false:
		return 3
	// CLOSE state
	case t.FIN == true || t.RST == true:
		return 4
	default:
		return 5
	}
}

//dumpConnTable prints out the contents of a connection table
func (c connTable) dumpConnTable() {

	fmt.Println("Connection Table")
	var table *tablewriter.Table
	table = newFormattedTableWriter()
	table.SetHeader([]string{"Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol", "Bytes", "Packets"})
	for i := range c {
		table.Append([]string{c[i][0].srcAddr.String(), strconv.Itoa(int(c[i][0].srcPort)), c[i][0].dstAddr.String(), strconv.Itoa(int(c[i][0].dstPort)), strconv.Itoa(int(c[i][0].protocol)), strconv.Itoa(c[i][0].account.bytes), strconv.Itoa(c[i][0].account.packets)})
	}
	table.Render()

}
