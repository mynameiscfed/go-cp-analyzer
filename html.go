package main

import (
	"fmt"
	"html/template"
	"os"
	"sort"
	"time"
)

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Packet Analysis Report</title>
    <style>
        :root {
            --primary-color: #00B4D8;
            --background-color:rgb(62, 62, 62);
            --text-color: #FFFFFF;
            --card-background: #2D2D2D;
            --border-color: #3D3D3D;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: var(--background-color);
            color: var(--text-color);
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
        }

        h1 {
            color: var(--primary-color);
            text-align: center;
            margin-bottom: 2rem;
        }

        .card {
            background-color: var(--card-background);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }

        .card h2 {
            color: var(--primary-color);
            margin-top: 0;
            margin-bottom: 1rem;
        }

        .metric-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1rem;
        }

        .metric {
            background-color: var(--background-color);
            padding: 1rem;
            border-radius: 4px;
            border: 1px solid var(--border-color);
        }

        .metric-label {
            color: #888;
            font-size: 0.9rem;
            margin-bottom: 0.5rem;
        }

        .metric-value {
            font-size: 1.2rem;
            font-weight: bold;
            color: var(--primary-color);
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
        }

        th, td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }

        th {
            background-color: var(--card-background);
            color: var(--primary-color);
        }

        tr:hover {
            background-color: var(--card-background);
        }

        .histogram-container {
			margin-top: 10px;
            margin-bottom: 2rem;
            padding: 2rem 0;
            background-color: var(--background-color);
            border-radius: 4px;
        }

        .histogram {
            display: flex;
            align-items: flex-end;
            height: 200px;
            gap: 4px;
            margin-top: 1rem;
            position: relative;
            padding: 0 1rem;
        }

        .bar {
            flex: 1;
            background-color: var(--primary-color);
            min-width: 20px;
            transition: height 0.3s ease;
            position: relative;
        }

        .bar:hover {
            opacity: 0.8;
        }

        .bar-label {
            position: absolute;
            bottom: -20px;
            left: 50%;
            transform: translateX(-50%);
            font-size: 0.8rem;
            color: var(--text-color);
            white-space: nowrap;
        }

        .bar-count {
            position: absolute;
            top: -20px;
            left: 50%;
            transform: translateX(-50%);
            font-size: 0.8rem;
            color: var(--text-color);
            white-space: nowrap;
        }

        .timestamp {
            text-align: center;
            color: #888;
            margin-top: 2rem;
        }

        /* Connection table styles */
        .filter-section {
            margin-bottom: 1rem;
        }

        .filter-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 1rem;
        }

        .filter-item {
            display: flex;
            flex-direction: column;
        }

        .filter-item label {
            color: #888;
            font-size: 0.9rem;
            margin-bottom: 0.5rem;
        }

        .filter-item input {
            background-color: var(--background-color);
            border: 1px solid var(--border-color);
            color: var(--text-color);
            padding: 0.5rem;
            border-radius: 4px;
            font-size: 0.9rem;
        }

        .filter-item input:focus {
            outline: none;
            border-color: var(--primary-color);
        }

        .table-container {
            overflow-x: auto;
            margin-top: 1rem;
        }

        #connectionTable {
            width: 100%;
            border-collapse: collapse;
        }

        #connectionTable th {
            position: sticky;
            top: 0;
            background-color: var(--card-background);
            z-index: 1;
        }

        #connectionTable tbody tr:nth-child(even) {
            background-color: var(--background-color);
        }

        #connectionTable tbody tr:hover {
            background-color: var(--card-background);
        }

        /* Pagination styles */
        .pagination {
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 1rem;
            margin-top: 1rem;
            padding: 0.5rem;
        }

        .pagination-btn {
            background-color: var(--primary-color);
            color: var(--text-color);
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.9rem;
            transition: opacity 0.2s;
        }

        .pagination-btn:hover {
            opacity: 0.8;
        }

        .pagination-btn:disabled {
            background-color: var(--border-color);
            cursor: not-allowed;
            opacity: 0.5;
        }

        #pageInfo {
            color: var(--text-color);
            font-size: 0.9rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Packet Analysis Report</h1>
        
        <div class="card">
            <h2>Overview</h2>
            <div class="metric-grid">
                <div class="metric">
                    <div class="metric-label">Total Packets</div>
                    <div class="metric-value">{{.TotalPackets}}</div>
                </div>
                <div class="metric">
                    <div class="metric-label">Total Bytes</div>
                    <div class="metric-value">{{.TotalBytes}}</div>
                </div>
                <div class="metric">
                    <div class="metric-label">Average Packet Size</div>
                    <div class="metric-value">{{.AvgPacketSize}} bytes</div>
                </div>
                <div class="metric">
                    <div class="metric-label">Capture Duration</div>
                    <div class="metric-value">{{.Duration}}</div>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>Protocol Distribution</h2>
            <div class="metric-grid">
                <div class="metric">
                    <div class="metric-label">Ethernet Packets</div>
                    <div class="metric-value">{{.EthernetPackets}}</div>
                </div>
                <div class="metric">
                    <div class="metric-label">TCP Packets</div>
                    <div class="metric-value">{{.TCPPackets}}</div>
                </div>
                <div class="metric">
                    <div class="metric-label">UDP Packets</div>
                    <div class="metric-value">{{.UDPPackets}}</div>
                </div>
                <div class="metric">
                    <div class="metric-label">Non-Ethernet Packets</div>
                    <div class="metric-value">{{.NonEthernetPackets}}</div>
                </div>
            </div>
            <table>
                <tr>
                    <th>Protocol Type</th>
                    <th>Count</th>
                </tr>
                {{range .ProtocolTypes}}
                <tr>
                    <td>{{.Name}}</td>
                    <td>{{.Count}}</td>
                </tr>
                {{end}}
            </table>
        </div>

        <div class="card">
            <h2>Packet Distribution</h2>
            <div class="metric-grid">
                <div class="metric">
                    <div class="metric-label">Total Packets</div>
                    <div class="metric-value">{{.TotalPackets}}</div>
                </div>
                <div class="metric">
                    <div class="metric-label">Average Packet Size</div>
                    <div class="metric-value">{{.AvgPacketSize}} bytes</div>
                </div>
                <div class="metric">
                    <div class="metric-label">Average Packets/Second</div>
                    <div class="metric-value">{{.AvgPacketsPerSecond}}</div>
                </div>
                <div class="metric">
                    <div class="metric-label">Average Throughput</div>
                    <div class="metric-value">{{.AvgThroughput}} Mbps</div>
                </div>
            </div>
            <div class="histogram-container">
                <div class="histogram">
                    {{range .PacketSizeBars}}
                    <div class="bar" style="height: {{.Height}}%" title="{{.Label}}: {{.Count}} packets">
                        <div class="bar-count">{{.Count}}</div>
                        <div class="bar-label">{{.Label}}</div>
                    </div>
                    {{end}}
                </div>
            </div>
            <table>
                <tr>
                    <th>Size Range</th>
                    <th>Count</th>
                </tr>
                {{range .PacketSizeStats}}
                <tr>
                    <td>{{.Range}}</td>
                    <td>{{.Count}}</td>
                </tr>
                {{end}}
            </table>
        </div>

        <div class="card">
            <h2>Top Connections</h2>
            <table>
                <tr>
                    <th>Source</th>
                    <th>Destination</th>
                    <th>Protocol</th>
                    <th>Bytes</th>
                    <th>Packets</th>
                </tr>
                {{range .TopConnections}}
                <tr>
                    <td>{{.Source}}</td>
                    <td>{{.Destination}}</td>
                    <td>{{.Protocol}}</td>
                    <td>{{.Bytes}}</td>
                    <td>{{.Packets}}</td>
                </tr>
                {{end}}
            </table>
        </div>

        <div class="card">
            <h2>Top Source IPs</h2>
            <table>
                <tr>
                    <th>IP Address</th>
                    <th>Connections</th>
                </tr>
                {{range .TopSourceIPs}}
                <tr>
                    <td>{{.IP}}</td>
                    <td>{{.Count}}</td>
                </tr>
                {{end}}
            </table>
        </div>

        <div class="card">
            <h2>Top Destination IPs</h2>
            <table>
                <tr>
                    <th>IP Address</th>
                    <th>Connections</th>
                </tr>
                {{range .TopDestIPs}}
                <tr>
                    <td>{{.IP}}</td>
                    <td>{{.Count}}</td>
                </tr>
                {{end}}
            </table>
        </div>

        <div class="card">
            <h2>All Connections</h2>
            <div class="filter-section">
                <div class="filter-grid">
                    <div class="filter-item">
                        <label>Source IP:</label>
                        <input type="text" id="srcIPFilter" placeholder="Filter by source IP">
                    </div>
					<div class="filter-item">
                        <label>Source Port:</label>
                        <input type="text" id="srcPortFilter" placeholder="Filter by source port">
                    </div>
                    <div class="filter-item">
                        <label>Destination IP:</label>
                        <input type="text" id="dstIPFilter" placeholder="Filter by destination IP">
                    </div>

                    <div class="filter-item">
                        <label>Destination Port:</label>
                        <input type="text" id="dstPortFilter" placeholder="Filter by destination port">
                    </div>
                    <div class="filter-item">
                        <label>Protocol:</label>
                        <input type="text" id="protoFilter" placeholder="Filter by protocol">
                    </div>
                </div>
            </div>
            <div class="table-container">
                <table id="connectionTable">
                    <thead>
                        <tr>
                            <th>Source IP:Port</th>
                            <th>Destination IP:Port</th>
                            <th>Protocol</th>
                            <th>Bytes</th>
                            <th>Packets</th>
                        </tr>
                    </thead>
                    <tbody>
                        {{range .AllConnections}}
                        <tr>
                            <td>{{.Source}}</td>
                            <td>{{.Destination}}</td>
                            <td>{{.Protocol}}</td>
                            <td>{{.Bytes}}</td>
                            <td>{{.Packets}}</td>
                        </tr>
                        {{end}}
                    </tbody>
                </table>
                <div class="pagination">
                    <button id="prevPage" class="pagination-btn">Previous</button>
                    <span id="pageInfo">Page 1 of 1</span>
                    <button id="nextPage" class="pagination-btn">Next</button>
                </div>
            </div>
        </div>

        <div class="timestamp">
            Generated on {{.Timestamp}}
        </div>
    </div>

    <script>
        // Connection table filtering and pagination functionality
        document.addEventListener('DOMContentLoaded', function() {
            const table = document.getElementById('connectionTable');
            const tbody = table.getElementsByTagName('tbody')[0];
            const rows = Array.from(tbody.getElementsByTagName('tr'));
            const filters = {
                srcIP: document.getElementById('srcIPFilter'),
                dstIP: document.getElementById('dstIPFilter'),
                srcPort: document.getElementById('srcPortFilter'),
                dstPort: document.getElementById('dstPortFilter'),
                proto: document.getElementById('protoFilter')
            };

            // Pagination elements
            const prevBtn = document.getElementById('prevPage');
            const nextBtn = document.getElementById('nextPage');
            const pageInfo = document.getElementById('pageInfo');

            let currentPage = 1;
            const rowsPerPage = 10;
            let filteredRows = [...rows];

            function updatePagination() {
                const totalPages = Math.ceil(filteredRows.length / rowsPerPage);
                pageInfo.textContent = "Page " + currentPage + " of " + totalPages;
                prevBtn.disabled = currentPage === 1;
                nextBtn.disabled = currentPage === totalPages;
            }

            function showPage(page) {
                const start = (page - 1) * rowsPerPage;
                const end = start + rowsPerPage;
                
                rows.forEach(row => {
                    row.style.display = 'none';
                });

                filteredRows.slice(start, end).forEach(row => {
                    row.style.display = '';
                });

                currentPage = page;
                updatePagination();
            }

            function filterTable() {
                const filterValues = {
                    srcIP: filters.srcIP.value.toLowerCase(),
                    dstIP: filters.dstIP.value.toLowerCase(),
                    srcPort: filters.srcPort.value.toLowerCase(),
                    dstPort: filters.dstPort.value.toLowerCase(),
                    proto: filters.proto.value.toLowerCase()
                };

                filteredRows = rows.filter(row => {
                    const cells = row.getElementsByTagName('td');
                    const source = cells[0].textContent.toLowerCase();
                    const destination = cells[1].textContent.toLowerCase();
                    const protocol = cells[2].textContent.toLowerCase();

                    // Split source and destination into IP and port
                    const [srcIP, srcPort] = source.split(':');
                    const [dstIP, dstPort] = destination.split(':');

                    return (!filterValues.srcIP || srcIP.includes(filterValues.srcIP)) &&
                           (!filterValues.dstIP || dstIP.includes(filterValues.dstIP)) &&
                           (!filterValues.srcPort || srcPort.includes(filterValues.srcPort)) &&
                           (!filterValues.dstPort || dstPort.includes(filterValues.dstPort)) &&
                           (!filterValues.proto || protocol.includes(filterValues.proto));
                });

                showPage(1); // Reset to first page when filtering
            }

            // Add event listeners to all filter inputs
            Object.values(filters).forEach(filter => {
                filter.addEventListener('input', filterTable);
            });

            // Add pagination event listeners
            prevBtn.addEventListener('click', () => {
                if (currentPage > 1) {
                    showPage(currentPage - 1);
                }
            });

            nextBtn.addEventListener('click', () => {
                const totalPages = Math.ceil(filteredRows.length / rowsPerPage);
                if (currentPage < totalPages) {
                    showPage(currentPage + 1);
                }
            });

            // Initialize the table
            showPage(1);
        });
    </script>
</body>
</html>`

type htmlReportData struct {
	TotalPackets        int
	TotalBytes          int
	AvgPacketSize       int
	Duration            string
	TCPPackets          int
	UDPPackets          int
	EthernetPackets     int
	NonEthernetPackets  int
	AvgPacketsPerSecond int
	AvgThroughput       float64
	ProtocolTypes       []struct {
		Name  string
		Count int
	}
	PacketSizeBars []struct {
		Height float64
		Label  string
		Count  int
	}
	PacketSizeStats []struct {
		Range string
		Count int
	}
	TopConnections []struct {
		Source      string
		Destination string
		Protocol    string
		Bytes       int
		Packets     int
	}
	TopSourceIPs []struct {
		IP    string
		Count int
	}
	TopDestIPs []struct {
		IP    string
		Count int
	}
	AllConnections []struct {
		Source      string
		Destination string
		Protocol    string
		Bytes       int
		Packets     int
	}
	Timestamp string
}

func generateHTMLReport(filename string) error {
	// Calculate total packets and duration
	var totalPackets int
	var firstPacketTime, lastPacketTime int
	for t := range ppsStats {
		totalPackets += ppsStats[t]
		if firstPacketTime == 0 || t < firstPacketTime {
			firstPacketTime = t
		}
		if t > lastPacketTime {
			lastPacketTime = t
		}
	}
	duration := time.Duration(lastPacketTime-firstPacketTime) * time.Second

	// Calculate average packets per second and throughput
	avgPacketsPerSecond := 0
	avgThroughput := 0.0
	if duration.Seconds() > 0 {
		avgPacketsPerSecond = int(float64(totalPackets) / duration.Seconds())
		avgThroughput = float64(totalBytes) * 8 / 1000000 / duration.Seconds() // Convert to Mbps
	}

	// Prepare packet size stats
	var packetSizeBars []struct {
		Height float64
		Label  string
		Count  int
	}
	var packetSizeStats []struct {
		Range string
		Count int
	}

	// Find max count for scaling
	maxCount := 0
	for _, count := range packetLengthStats {
		if count > maxCount {
			maxCount = count
		}
	}

	// Sort packet sizes
	var sizes []int
	for size := range packetLengthStats {
		sizes = append(sizes, size)
	}
	sort.Ints(sizes)

	// Generate bars and stats
	for _, size := range sizes {
		count := packetLengthStats[size]
		height := 0.0
		if maxCount > 0 {
			height = float64(count) / float64(maxCount) * 100
		}
		packetSizeBars = append(packetSizeBars, struct {
			Height float64
			Label  string
			Count  int
		}{
			Height: height,
			Label:  fmt.Sprintf("≤ %d bytes", size),
			Count:  count,
		})

		packetSizeStats = append(packetSizeStats, struct {
			Range string
			Count int
		}{
			Range: fmt.Sprintf("≤ %d bytes", size),
			Count: count,
		})
	}

	// Prepare top connections
	var topConnections []struct {
		Source      string
		Destination string
		Protocol    string
		Bytes       int
		Packets     int
	}

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

	n := 10
	if len(conns) < n {
		n = len(conns)
	}

	for i := 0; i < n; i++ {
		conn := connectionTable[conns[i].hash][0]
		proto := "TCP"
		if conn.protocol == 17 {
			proto = "UDP"
		}
		topConnections = append(topConnections, struct {
			Source      string
			Destination string
			Protocol    string
			Bytes       int
			Packets     int
		}{
			Source:      fmt.Sprintf("%s:%d", conn.srcAddr.String(), conn.srcPort),
			Destination: fmt.Sprintf("%s:%d", conn.dstAddr.String(), conn.dstPort),
			Protocol:    proto,
			Bytes:       conn.account.bytes,
			Packets:     conn.account.packets,
		})
	}

	// Prepare top source IPs
	ipCounts := make(map[string]int)
	for _, conn := range connectionTable {
		ipCounts[conn[0].srcAddr.String()]++
	}

	type ipCount struct {
		ip    string
		count int
	}
	var sourceIPs []ipCount
	for ip, count := range ipCounts {
		sourceIPs = append(sourceIPs, ipCount{ip, count})
	}
	sort.Slice(sourceIPs, func(i, j int) bool {
		return sourceIPs[i].count > sourceIPs[j].count
	})

	var topSourceIPs []struct {
		IP    string
		Count int
	}
	n = 10
	if len(sourceIPs) < n {
		n = len(sourceIPs)
	}
	for i := 0; i < n; i++ {
		topSourceIPs = append(topSourceIPs, struct {
			IP    string
			Count int
		}{
			IP:    sourceIPs[i].ip,
			Count: sourceIPs[i].count,
		})
	}

	// Prepare top destination IPs
	ipCounts = make(map[string]int)
	for _, conn := range connectionTable {
		ipCounts[conn[0].dstAddr.String()]++
	}

	var destIPs []ipCount
	for ip, count := range ipCounts {
		destIPs = append(destIPs, ipCount{ip, count})
	}
	sort.Slice(destIPs, func(i, j int) bool {
		return destIPs[i].count > destIPs[j].count
	})

	var topDestIPs []struct {
		IP    string
		Count int
	}
	n = 10
	if len(destIPs) < n {
		n = len(destIPs)
	}
	for i := 0; i < n; i++ {
		topDestIPs = append(topDestIPs, struct {
			IP    string
			Count int
		}{
			IP:    destIPs[i].ip,
			Count: destIPs[i].count,
		})
	}

	// Prepare all connections
	var allConnections []struct {
		Source      string
		Destination string
		Protocol    string
		Bytes       int
		Packets     int
	}

	for _, conn := range connectionTable {
		allConnections = append(allConnections, struct {
			Source      string
			Destination string
			Protocol    string
			Bytes       int
			Packets     int
		}{
			Source:      fmt.Sprintf("%s:%d", conn[0].srcAddr.String(), conn[0].srcPort),
			Destination: fmt.Sprintf("%s:%d", conn[0].dstAddr.String(), conn[0].dstPort),
			Protocol:    fmt.Sprintf("%d", conn[0].protocol),
			Bytes:       conn[0].account.bytes,
			Packets:     conn[0].account.packets,
		})
	}

	// Prepare protocol types
	var protocolTypes []struct {
		Name  string
		Count int
	}
	for name, count := range etherType {
		protocolTypes = append(protocolTypes, struct {
			Name  string
			Count int
		}{
			Name:  name,
			Count: count,
		})
	}
	sort.Slice(protocolTypes, func(i, j int) bool {
		return protocolTypes[i].Count > protocolTypes[j].Count
	})

	// Prepare report data
	data := htmlReportData{
		TotalPackets:        totalPackets,
		TotalBytes:          totalBytes,
		AvgPacketSize:       totalBytes / totalPackets,
		Duration:            duration.String(),
		TCPPackets:          tcpStats["count"],
		UDPPackets:          udpStats["count"],
		EthernetPackets:     ethernetStats["count"],
		NonEthernetPackets:  ethernetStats["countErr"],
		AvgPacketsPerSecond: avgPacketsPerSecond,
		AvgThroughput:       avgThroughput,
		ProtocolTypes:       protocolTypes,
		PacketSizeBars:      packetSizeBars,
		PacketSizeStats:     packetSizeStats,
		TopConnections:      topConnections,
		TopSourceIPs:        topSourceIPs,
		TopDestIPs:          topDestIPs,
		AllConnections:      allConnections,
		Timestamp:           time.Now().Format("2006-01-02 15:04:05"),
	}

	// Parse and execute template
	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("error parsing template: %v", err)
	}

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("error creating file: %v", err)
	}
	defer file.Close()

	if err := tmpl.Execute(file, data); err != nil {
		return fmt.Errorf("error executing template: %v", err)
	}

	return nil
}
