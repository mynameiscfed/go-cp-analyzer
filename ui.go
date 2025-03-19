package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	// Modern minimalist color palette
	background = lipgloss.Color("#1E1E1E") // Dark background
	text       = lipgloss.Color("#FFFFFF") // White text
	accent     = lipgloss.Color("#00B4D8") // Bright cyan accent

	// Global background style
	backgroundStyle = lipgloss.NewStyle().
			Background(background).
			Padding(1, 2)

	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(text).
			Background(background).
			Padding(0, 2).
			MarginBottom(1)

	// Menu bar styles
	menuBarStyle = lipgloss.NewStyle().
			Background(background).
			Padding(0, 1).
			MarginBottom(1)

	tabStyle = lipgloss.NewStyle().
			Padding(0, 2).
			MarginRight(1).
			Foreground(text).
			Background(background)

	activeTabStyle = lipgloss.NewStyle().
			Padding(0, 2).
			MarginRight(1).
			Foreground(text).
			Background(accent).
			Bold(true)

	tableStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(accent).
			Background(background).
			Padding(1, 2).
			MarginTop(1)

	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(accent).
			MarginBottom(1)

	sectionStyle = lipgloss.NewStyle().
			Foreground(accent).
			Bold(true).
			MarginBottom(1)

	selectedStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(text).
			Background(accent).
			Padding(0, 1)

	filterStyle = lipgloss.NewStyle().
			Foreground(text).
			Background(background).
			Padding(0, 1)

	metricStyle = lipgloss.NewStyle().
			Background(background).
			Foreground(text).
			Padding(0, 1)

	scrollIndicatorStyle = lipgloss.NewStyle().
				Foreground(text).
				Italic(true)

	metricValueStyle = lipgloss.NewStyle().
				Background(background).
				Foreground(accent).
				Bold(false)

	metricLabelStyle = lipgloss.NewStyle().
				Foreground(text)
)

type filterField int

const (
	srcIP filterField = iota
	dstIP
	srcPort
	dstPort
	proto
)

type model struct {
	activeTab     int
	tabs          []string
	activeFilter  filterField
	srcIPFilter   string
	dstIPFilter   string
	srcPortFilter string
	dstPortFilter string
	protoFilter   string
	filteredConns []connection
	editing       bool
	scrollPos     int // Current scroll position for connections list
}

func initialModel() model {
	return model{
		tabs: []string{
			"Packet Stats",
			"Protocol Stats",
			"Connection Stats",
			"Top Connections",
			"Top Source IPs",
			"Top Dest IPs",
			"Connection Browser",
		},
		activeTab:     0,
		filteredConns: getInitialConnections(),
	}
}

func getInitialConnections() []connection {
	var conns []connection
	for _, connSlice := range connectionTable {
		conns = append(conns, connSlice[0])
	}
	return conns
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "left":
			if !m.editing {
				if m.activeTab > 0 {
					m.activeTab--
				}
			}
		case "right":
			if !m.editing {
				if m.activeTab < len(m.tabs)-1 {
					m.activeTab++
				}
			}
		case "up":
			if m.activeTab == 6 { // Connection Browser tab
				if m.editing {
					// Handle filter editing
					if m.activeFilter > srcIP {
						m.activeFilter--
					}
				} else {
					// Handle scrolling
					if m.scrollPos > 0 {
						m.scrollPos--
					}
				}
			}
		case "down":
			if m.activeTab == 6 { // Connection Browser tab
				if m.editing {
					// Handle filter editing
					if m.activeFilter < proto {
						m.activeFilter++
					}
				} else {
					// Handle scrolling
					maxScroll := len(m.filteredConns) - 10 // Show 10 connections at a time
					if m.scrollPos < maxScroll {
						m.scrollPos++
					}
				}
			}
		case "enter":
			if m.activeTab == 6 { // Connection Browser tab
				m.editing = !m.editing
				if !m.editing {
					m.applyFilters()
					m.scrollPos = 0 // Reset scroll position when filters change
				}
			}
		case "esc":
			if m.editing {
				m.editing = false
			}
		case "backspace":
			if m.editing {
				switch m.activeFilter {
				case srcIP:
					if len(m.srcIPFilter) > 0 {
						m.srcIPFilter = m.srcIPFilter[:len(m.srcIPFilter)-1]
					}
				case dstIP:
					if len(m.dstIPFilter) > 0 {
						m.dstIPFilter = m.dstIPFilter[:len(m.dstIPFilter)-1]
					}
				case srcPort:
					if len(m.srcPortFilter) > 0 {
						m.srcPortFilter = m.srcPortFilter[:len(m.srcPortFilter)-1]
					}
				case dstPort:
					if len(m.dstPortFilter) > 0 {
						m.dstPortFilter = m.dstPortFilter[:len(m.dstPortFilter)-1]
					}
				case proto:
					if len(m.protoFilter) > 0 {
						m.protoFilter = m.protoFilter[:len(m.protoFilter)-1]
					}
				}
			}
		default:
			if m.editing {
				switch m.activeFilter {
				case srcIP:
					m.srcIPFilter += msg.String()
				case dstIP:
					m.dstIPFilter += msg.String()
				case srcPort:
					if isNumeric(msg.String()) {
						m.srcPortFilter += msg.String()
					}
				case dstPort:
					if isNumeric(msg.String()) {
						m.dstPortFilter += msg.String()
					}
				case proto:
					if isNumeric(msg.String()) {
						m.protoFilter += msg.String()
					}
				}
			}
		}
	}
	return m, nil
}

func isNumeric(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

func (m *model) applyFilters() {
	var filtered []connection
	for _, connSlice := range connectionTable {
		conn := connSlice[0]
		if m.matchesFilters(conn) {
			filtered = append(filtered, conn)
		}
	}
	m.filteredConns = filtered
}

func (m *model) matchesFilters(conn connection) bool {
	if m.srcIPFilter != "" && !strings.Contains(conn.srcAddr.String(), m.srcIPFilter) {
		return false
	}
	if m.dstIPFilter != "" && !strings.Contains(conn.dstAddr.String(), m.dstIPFilter) {
		return false
	}
	if m.srcPortFilter != "" {
		port, err := strconv.Atoi(m.srcPortFilter)
		if err == nil && int(conn.srcPort) != port {
			return false
		}
	}
	if m.dstPortFilter != "" {
		port, err := strconv.Atoi(m.dstPortFilter)
		if err == nil && int(conn.dstPort) != port {
			return false
		}
	}
	if m.protoFilter != "" {
		proto, err := strconv.Atoi(m.protoFilter)
		if err == nil && int(conn.protocol) != proto {
			return false
		}
	}
	return true
}

func (m model) View() string {
	s := strings.Builder{}

	// Title
	s.WriteString(titleStyle.Render("Go Captured Packet Analyzer"))
	s.WriteString("\n")

	// Menu bar
	menuBar := strings.Builder{}
	menuBar.WriteString(menuBarStyle.Render(""))
	for i, tab := range m.tabs {
		if i == m.activeTab {
			menuBar.WriteString(activeTabStyle.Render(tab))
		} else {
			menuBar.WriteString(tabStyle.Render(tab))
		}
	}
	menuBar.WriteString(menuBarStyle.Render(""))
	s.WriteString(menuBar.String())
	s.WriteString("\n\n")

	// Content based on active tab
	switch m.activeTab {
	case 0:
		s.WriteString(m.renderPacketStats())
	case 1:
		s.WriteString(m.renderProtocolStats())
	case 2:
		s.WriteString(m.renderConnStats())
	case 3:
		s.WriteString(m.renderTopConns())
	case 4:
		s.WriteString(m.renderTopSrc())
	case 5:
		s.WriteString(m.renderTopDst())
	case 6:
		s.WriteString(m.renderConnectionBrowser())
	}

	return backgroundStyle.Render(s.String())
}

func (m model) renderConnectionBrowser() string {
	var content []string

	// Header with enterprise styling
	content = append(content, sectionStyle.Render("Connection Browser"))
	content = append(content, "")

	// Filters section with improved visual hierarchy
	content = append(content, headerStyle.Render("Filters"))
	content = append(content, metricLabelStyle.Render("Press Enter to edit, Esc to finish"))
	content = append(content, "")

	filterLabels := []struct {
		field filterField
		name  string
		value string
	}{
		{srcIP, "Source IP", m.srcIPFilter},
		{dstIP, "Destination IP", m.dstIPFilter},
		{srcPort, "Source Port", m.srcPortFilter},
		{dstPort, "Destination Port", m.dstPortFilter},
		{proto, "Protocol", m.protoFilter},
	}

	for _, f := range filterLabels {
		line := metricLabelStyle.Render(f.name + ": ")
		if m.activeFilter == f.field {
			if m.editing {
				line += selectedStyle.Render(f.value + "▊")
			} else {
				line += selectedStyle.Render(f.value)
			}
		} else {
			line += filterStyle.Render(f.value)
		}
		content = append(content, line)
	}

	content = append(content, "")
	content = append(content, metricStyle.Render(fmt.Sprintf("Showing %d connections", len(m.filteredConns))))
	content = append(content, "")

	// Connections table header with improved styling
	content = append(content, headerStyle.Render("Active Connections"))
	content = append(content, metricLabelStyle.Render("Source IP:Port → Destination IP:Port (Proto) [Bytes/Packets]"))
	content = append(content, strings.Repeat("─", 70))

	// Calculate visible range
	start := m.scrollPos
	end := start + 10
	if end > len(m.filteredConns) {
		end = len(m.filteredConns)
	}

	// Render visible connections with improved formatting
	for i := start; i < end; i++ {
		conn := m.filteredConns[i]
		line := fmt.Sprintf("%d. %s:%d → %s:%d (%d) [%d/%d]",
			i+1,
			conn.srcAddr.String(),
			conn.srcPort,
			conn.dstAddr.String(),
			conn.dstPort,
			conn.protocol,
			conn.account.bytes,
			conn.account.packets)
		content = append(content, metricStyle.Render(line))
	}

	// Add scroll indicator with improved styling
	if len(m.filteredConns) > 10 {
		content = append(content, "")
		content = append(content, scrollIndicatorStyle.Render(fmt.Sprintf("Showing entries %d-%d of %d (Use ↑↓ to scroll)",
			start+1, end, len(m.filteredConns))))
	}

	return tableStyle.Render(strings.Join(content, "\n"))
}

func (m model) renderPacketStats() string {
	var stats []string
	stats = append(stats, sectionStyle.Render("Packet Distribution"))
	stats = append(stats, "")

	// Sort packetLengthStats
	var keys []int
	for k := range packetLengthStats {
		keys = append(keys, k)
	}
	sort.Ints(keys)

	// Find max count for scaling
	maxCount := 0
	for _, count := range packetLengthStats {
		if count > maxCount {
			maxCount = count
		}
	}

	// Calculate bar width (max 50 characters)
	barWidth := 50
	if maxCount == 0 {
		maxCount = 1 // Prevent division by zero
	}

	// Render histogram
	for _, k := range keys {
		count := packetLengthStats[k]
		barLength := (count * barWidth) / maxCount
		bar := strings.Repeat("█", barLength)
		stats = append(stats, metricStyle.Render(fmt.Sprintf("≤ %-5d: %-6d %s", k, count, bar)))
	}

	stats = append(stats, "")
	stats = append(stats, sectionStyle.Render("Performance Metrics"))
	stats = append(stats, "")

	// Calculate metrics
	totalPackets := 0
	for _, j := range ppsStats {
		totalPackets += j
	}

	var e []int
	for f := range ppsStats {
		e = append(e, f)
	}
	sort.Ints(e)
	firstPacketTime := e[0]
	lastPacketTime := e[len(e)-1]
	totalTime := lastPacketTime - firstPacketTime

	packetRate := totalPackets / totalTime
	averagePacketSize := totalBytes / totalPackets
	averageThrougput := totalBytes / totalTime

	// Render metrics with improved formatting
	stats = append(stats, metricLabelStyle.Render("Total Packets: ")+metricValueStyle.Render(fmt.Sprintf("%d", totalPackets)))
	stats = append(stats, metricLabelStyle.Render("Average Packet Size: ")+metricValueStyle.Render(fmt.Sprintf("%d bytes", averagePacketSize)))
	stats = append(stats, metricLabelStyle.Render("Average Packets/Second: ")+metricValueStyle.Render(fmt.Sprintf("%d", packetRate)))
	stats = append(stats, metricLabelStyle.Render("Average Throughput: ")+metricValueStyle.Render(fmt.Sprintf("%.2f Mbps", float64(averageThrougput)*0.000008)))

	return tableStyle.Render(strings.Join(stats, "\n"))
}

func (m model) renderProtocolStats() string {
	var stats []string
	stats = append(stats, sectionStyle.Render("Protocol Statistics"))
	stats = append(stats, "")

	stats = append(stats, metricLabelStyle.Render("Ethernet packets: ")+metricValueStyle.Render(fmt.Sprintf("%d", ethernetStats["count"])))
	stats = append(stats, metricLabelStyle.Render("TCP packets: ")+metricValueStyle.Render(fmt.Sprintf("%d", tcpStats["count"])))
	stats = append(stats, metricLabelStyle.Render("UDP packets: ")+metricValueStyle.Render(fmt.Sprintf("%d", udpStats["count"])))
	stats = append(stats, metricLabelStyle.Render("Non-Ethernet packets: ")+metricValueStyle.Render(fmt.Sprintf("%d", ethernetStats["countErr"])))

	// Sort protocols
	var protocols []string
	for p := range etherType {
		protocols = append(protocols, p)
	}
	sort.Strings(protocols)

	for _, p := range protocols {
		stats = append(stats, metricLabelStyle.Render(p+": ")+metricValueStyle.Render(fmt.Sprintf("%d", etherType[p])))
	}

	return tableStyle.Render(strings.Join(stats, "\n"))
}

func (m model) renderConnStats() string {
	var stats []string
	stats = append(stats, sectionStyle.Render("Connection Statistics"))
	stats = append(stats, "")

	var e []int
	for f := range ppsStats {
		e = append(e, f)
	}
	sort.Ints(e)
	firstPacketTime := e[0]
	lastPacketTime := e[len(e)-1]
	totalTime := lastPacketTime - firstPacketTime

	// TCP stats
	totalTCPConns := 0
	maxTCPConnsSec := 0
	for _, j := range newTCPConnectionsCreated {
		totalTCPConns += j
		if j > maxTCPConnsSec {
			maxTCPConnsSec = j
		}
	}
	tcpConnsPerSecond := totalTCPConns / totalTime

	// UDP stats
	totalUDPConns := 0
	maxUDPConnsSec := 0
	for _, j := range udpConnectionsStats {
		totalUDPConns += j
		if j > maxUDPConnsSec {
			maxUDPConnsSec = j
		}
	}
	udpConnsPerSecond := totalUDPConns / totalTime

	stats = append(stats, headerStyle.Render("TCP Connections:"))
	stats = append(stats, metricLabelStyle.Render("  Total: ")+metricValueStyle.Render(fmt.Sprintf("%d", totalTCPConns)))
	stats = append(stats, metricLabelStyle.Render("  Average per second: ")+metricValueStyle.Render(fmt.Sprintf("%d", tcpConnsPerSecond)))
	stats = append(stats, metricLabelStyle.Render("  Peak per second: ")+metricValueStyle.Render(fmt.Sprintf("%d", maxTCPConnsSec)))

	stats = append(stats, "")
	stats = append(stats, headerStyle.Render("UDP Connections:"))
	stats = append(stats, metricLabelStyle.Render("  Total: ")+metricValueStyle.Render(fmt.Sprintf("%d", totalUDPConns)))
	stats = append(stats, metricLabelStyle.Render("  Average per second: ")+metricValueStyle.Render(fmt.Sprintf("%d", udpConnsPerSecond)))
	stats = append(stats, metricLabelStyle.Render("  Peak per second: ")+metricValueStyle.Render(fmt.Sprintf("%d", maxUDPConnsSec)))

	return tableStyle.Render(strings.Join(stats, "\n"))
}

func (m model) renderTopConns() string {
	if len(connectionTable) < 1 {
		return metricStyle.Render("No connection data available")
	}

	var stats []string
	stats = append(stats, sectionStyle.Render("Top Connections by Bytes"))
	stats = append(stats, "")

	// Sort connections by bytes
	type connBytes struct {
		hash  int
		bytes int
	}
	var conns []connBytes
	for hash, conn := range connectionTable {
		conns = append(conns, connBytes{hash, conn[0].account.bytes})
	}
	sort.Slice(conns, func(i, j int) bool {
		return conns[i].bytes > conns[j].bytes
	})

	// Take top 10
	n := 10
	if len(conns) < n {
		n = len(conns)
	}

	for i := 0; i < n; i++ {
		conn := connectionTable[conns[i].hash][0]
		line := fmt.Sprintf("%d. %s:%d → %s:%d (%d bytes, %d packets)",
			i+1,
			conn.srcAddr.String(),
			conn.srcPort,
			conn.dstAddr.String(),
			conn.dstPort,
			conn.account.bytes,
			conn.account.packets)
		stats = append(stats, metricStyle.Render(line))
	}

	stats = append(stats, "")
	stats = append(stats, scrollIndicatorStyle.Render(fmt.Sprintf("Showing entries 1-%d of %d", n, len(conns))))

	return tableStyle.Render(strings.Join(stats, "\n"))
}

func (m model) renderTopSrc() string {
	if len(connectionTable) < 1 {
		return metricStyle.Render("No connection data available")
	}

	var stats []string
	stats = append(stats, sectionStyle.Render("Top Source IP Addresses"))
	stats = append(stats, "")

	// Count source IPs
	ipCounts := make(map[string]int)
	for _, conn := range connectionTable {
		ipCounts[conn[0].srcAddr.String()]++
	}

	// Sort IPs by count
	type ipCount struct {
		ip    string
		count int
	}
	var ips []ipCount
	for ip, count := range ipCounts {
		ips = append(ips, ipCount{ip, count})
	}
	sort.Slice(ips, func(i, j int) bool {
		return ips[i].count > ips[j].count
	})

	// Take top 10
	n := 10
	if len(ips) < n {
		n = len(ips)
	}

	for i := 0; i < n; i++ {
		line := fmt.Sprintf("%d. %s (%d connections)",
			i+1,
			ips[i].ip,
			ips[i].count)
		stats = append(stats, metricStyle.Render(line))
	}

	return tableStyle.Render(strings.Join(stats, "\n"))
}

func (m model) renderTopDst() string {
	if len(connectionTable) < 1 {
		return metricStyle.Render("No connection data available")
	}

	var stats []string
	stats = append(stats, sectionStyle.Render("Top Destination IP Addresses"))
	stats = append(stats, "")

	// Count destination IPs
	ipCounts := make(map[string]int)
	for _, conn := range connectionTable {
		ipCounts[conn[0].dstAddr.String()]++
	}

	// Sort IPs by count
	type ipCount struct {
		ip    string
		count int
	}
	var ips []ipCount
	for ip, count := range ipCounts {
		ips = append(ips, ipCount{ip, count})
	}
	sort.Slice(ips, func(i, j int) bool {
		return ips[i].count > ips[j].count
	})

	// Take top 10
	n := 10
	if len(ips) < n {
		n = len(ips)
	}

	for i := 0; i < n; i++ {
		line := fmt.Sprintf("%d. %s (%d connections)",
			i+1,
			ips[i].ip,
			ips[i].count)
		stats = append(stats, metricStyle.Render(line))
	}

	return tableStyle.Render(strings.Join(stats, "\n"))
}
