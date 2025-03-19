package main

import (
	"net"
)

// connTable represents a map of connection hashes to slices of connections.
// The key is the connection hash, and the value is a slice of connections
// that share the same hash (handles potential hash collisions).
type connTable map[int][]connection

// connection represents a network connection with its source and destination information,
// protocol details, connection state, and traffic accounting.
type connection struct {
	srcAddr   net.IP     // Source IP address
	dstAddr   net.IP     // Destination IP address
	srcPort   uint16     // Source port number
	dstPort   uint16     // Destination port number
	protocol  uint8      // IP protocol number (e.g., TCP=6, UDP=17)
	connState uint8      // Current connection state
	account   accounting // Traffic accounting information
}

// accounting holds traffic statistics for a connection
type accounting struct {
	bytes   int // Total number of bytes transferred
	packets int // Total number of packets transferred
}

// tcpState represents the TCP flags present in a packet
type tcpState struct {
	SYN bool // Synchronize sequence numbers
	ACK bool // Acknowledgment field significant
	PSH bool // Push function
	FIN bool // No more data from sender
	RST bool // Reset the connection
}

// ConnectionDirection represents the direction of a network connection
type ConnectionDirection uint8

const (
	NoDirection    ConnectionDirection = iota // No connection direction determined
	ClientToServer                            // Connection from client to server
	ServerToClient                            // Connection from server to client
)

// TCPState represents the possible states of a TCP connection
type TCPState uint8

const (
	StateUnknown     TCPState = iota // Initial or unknown state
	StateSynSent                     // SYN packet sent, waiting for SYN-ACK
	StateSynReceived                 // SYN-ACK received, connection established
	StateEstablished                 // Connection is established and active
	StateFinWait1                    // First FIN sent, waiting for ACK
	StateFinWait2                    // ACK received for first FIN, waiting for second FIN
	StateCloseWait                   // Received FIN, waiting for local close
	StateLastAck                     // Last ACK sent, waiting for timeout
	StateClosing                     // Both sides have sent FIN, waiting for last ACK
	StateTimeWait                    // Connection is in TIME_WAIT state
	StateClosed                      // Connection is closed
	StateReset                       // Connection was reset
)

// ipToBytes converts an IP address to a byte slice, handling both IPv4 and IPv6.
// For IPv4 addresses, it converts them to a 16-byte format by padding with zeros.
// For IPv6 addresses, it returns the full 16 bytes.
//
// Parameters:
//   - ip: The IP address to convert
//
// Returns:
//   - []byte: The IP address as a byte slice
func ipToBytes(ip net.IP) []byte {
	// If the IP is in IPv4 format, convert it to 16 bytes
	if ip4 := ip.To4(); ip4 != nil {
		ip = make(net.IP, 16)
		copy(ip[12:], ip4)
	}
	return ip
}

// connectionHash creates a hash for connection tracking that works with both IPv4 and IPv6.
// It uses the FNV-1a hashing algorithm for good distribution and combines the 5-tuple
// (source IP, destination IP, source port, destination port, protocol) into a single hash.
//
// Parameters:
//   - srcIP: Source IP address
//   - dstIP: Destination IP address
//   - srcPort: Source port number
//   - dstPort: Destination port number
//   - ipProto: IP protocol number
//
// Returns:
//   - int: A hash value that uniquely identifies the connection
func connectionHash(srcIP net.IP, dstIP net.IP, srcPort uint16, dstPort uint16, ipProto uint8) int {
	// Convert IPs to byte slices
	srcBytes := ipToBytes(srcIP)
	dstBytes := ipToBytes(dstIP)

	// Use FNV-1a hash for better distribution
	h := uint64(14695981039346656037) // FNV-1a offset basis

	// Hash source IP
	for _, b := range srcBytes {
		h ^= uint64(b)
		h *= 1099511628211 // FNV-1a prime
	}

	// Hash destination IP
	for _, b := range dstBytes {
		h ^= uint64(b)
		h *= 1099511628211
	}

	// Hash ports and protocol
	h ^= uint64(srcPort)
	h *= 1099511628211
	h ^= uint64(dstPort)
	h *= 1099511628211
	h ^= uint64(ipProto)
	h *= 1099511628211

	return int(h)
}

// connectionLookup searches the connection table for an existing connection.
// It checks both directions of the connection (client->server and server->client)
// to handle bidirectional traffic properly.
//
// Parameters:
//   - srcIP: Source IP address
//   - dstIP: Destination IP address
//   - srcPort: Source port number
//   - dstPort: Destination port number
//   - ipProto: IP protocol number
//
// Returns:
//   - bool: Whether the connection exists
//   - int: The hash value of the connection if found
//   - ConnectionDirection: The direction of the connection (ClientToServer or ServerToClient)
func connectionLookup(srcIP net.IP, dstIP net.IP, srcPort uint16, dstPort uint16, ipProto uint8) (bool, int, ConnectionDirection) {
	// Check both directions of the connection
	clientToServerHash := connectionHash(srcIP, dstIP, srcPort, dstPort, ipProto)
	serverToClientHash := connectionHash(dstIP, srcIP, dstPort, srcPort, ipProto)

	// First check client->server direction
	if conns, ok := connectionTable[clientToServerHash]; ok && len(conns) > 0 {
		return true, clientToServerHash, ClientToServer
	}

	// Then check server->client direction
	if conns, ok := connectionTable[serverToClientHash]; ok && len(conns) > 0 {
		return true, serverToClientHash, ServerToClient
	}

	return false, 0, NoDirection
}

// checkTCPState determines the TCP state based on the TCP flags present in a packet.
// It implements a simplified TCP state machine that handles the most common states
// and transitions. The function prioritizes RST packets and handles connection
// establishment, data transfer, and termination states.
//
// Parameters:
//   - t: The TCP flags present in the packet
//
// Returns:
//   - uint8: The connection state (1=C->S connection, 2=S->C reply, 3=established/ACK only, 4=FIN/RST, 5=no match)
func checkTCPState(t tcpState) uint8 {
	// Handle RST first as it overrides other states
	if t.RST {
		return 4 // FIN/RST state
	}

	// Handle connection establishment
	if t.SYN && !t.ACK {
		return 1 // C->S connection
	}
	if t.SYN && t.ACK {
		return 2 // S->C reply
	}

	// Handle connection termination
	if t.FIN {
		return 4 // FIN/RST state
	}

	// Handle established connection
	if t.ACK && !t.SYN && !t.FIN {
		return 3 // established/ACK only
	}

	// Handle PSH flag in established state
	if t.PSH && t.ACK {
		return 3 // established/ACK only
	}

	return 5 // no match
}
