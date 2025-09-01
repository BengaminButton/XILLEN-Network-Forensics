package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type PacketInfo struct {
	Timestamp      time.Time `json:"timestamp"`
	Length         int       `json:"length"`
	Protocol       string    `json:"protocol"`
	SourceIP       string    `json:"source_ip"`
	DestIP         string    `json:"dest_ip"`
	SourcePort     uint16    `json:"source_port"`
	DestPort       uint16    `json:"dest_port"`
	Payload        string    `json:"payload"`
	Flags          string    `json:"flags"`
	WindowSize     uint16    `json:"window_size"`
	SequenceNum    uint32    `json:"sequence_num"`
	ACKNum         uint32    `json:"ack_num"`
	TTL            uint8     `json:"ttl"`
	Checksum       uint16    `json:"checksum"`
	FragmentID     uint16    `json:"fragment_id"`
	FragmentOffset uint16    `json:"fragment_offset"`
	MoreFragments  bool      `json:"more_fragments"`
	DNSQuery       string    `json:"dns_query"`
	DNSResponse    string    `json:"dns_response"`
	HTTPMethod     string    `json:"http_method"`
	HTTPHost       string    `json:"http_host"`
	HTTPPath       string    `json:"http_path"`
	HTTPUserAgent  string    `json:"http_user_agent"`
	ICMPType       uint8     `json:"icmp_type"`
	ICMPCode       uint8     `json:"icmp_code"`
}

type Connection struct {
	SourceIP   string    `json:"source_ip"`
	DestIP     string    `json:"dest_ip"`
	SourcePort uint16    `json:"source_port"`
	DestPort   uint16    `json:"dest_port"`
	Protocol   string    `json:"protocol"`
	StartTime  time.Time `json:"start_time"`
	EndTime    time.Time `json:"end_time"`
	Packets    int       `json:"packets"`
	Bytes      int       `json:"bytes"`
	Status     string    `json:"status"`
}

type ForensicReport struct {
	CaptureInfo struct {
		Interface    string    `json:"interface"`
		StartTime    time.Time `json:"start_time"`
		EndTime      time.Time `json:"end_time"`
		TotalPackets int       `json:"total_packets"`
		TotalBytes   int       `json:"total_bytes"`
		Duration     string    `json:"duration"`
	} `json:"capture_info"`

	NetworkStats struct {
		UniqueIPs      int `json:"unique_ips"`
		UniquePorts    int `json:"unique_ports"`
		TCPConnections int `json:"tcp_connections"`
		UDPConnections int `json:"udp_connections"`
		ICMPPackets    int `json:"icmp_packets"`
		HTTPRequests   int `json:"http_requests"`
		DNSQueries     int `json:"dns_queries"`
	} `json:"network_stats"`

	TopTalkers []struct {
		IP      string `json:"ip"`
		Packets int    `json:"packets"`
		Bytes   int    `json:"bytes"`
	} `json:"top_talkers"`

	TopPorts []struct {
		Port    uint16 `json:"port"`
		Packets int    `json:"packets"`
		Bytes   int    `json:"bytes"`
	} `json:"top_ports"`

	Anomalies []struct {
		Type        string `json:"type"`
		Description string `json:"description"`
		Severity    string `json:"severity"`
		Timestamp   string `json:"timestamp"`
	} `json:"anomalies"`

	Connections []Connection `json:"connections"`
}

type NetworkForensics struct {
	interfaceName string
	filter        string
	outputFile    string
	outputFormat  string
	packetLimit   int
	timeout       time.Duration
	verbose       bool

	packets     []PacketInfo
	connections map[string]*Connection
	ipStats     map[string]int
	portStats   map[uint16]int
	anomalies   []string

	mutex        sync.RWMutex
	startTime    time.Time
	endTime      time.Time
	totalPackets int
	totalBytes   int
}

func NewNetworkForensics() *NetworkForensics {
	return &NetworkForensics{
		connections: make(map[string]*Connection),
		ipStats:     make(map[string]int),
		portStats:   make(map[uint16]int),
		anomalies:   make([]string, 0),
	}
}

func (nf *NetworkForensics) parseFlags() {
	flag.StringVar(&nf.interfaceName, "i", "", "Network interface to capture")
	flag.StringVar(&nf.filter, "f", "", "BPF filter expression")
	flag.StringVar(&nf.outputFile, "o", "forensics_report", "Output file name")
	flag.StringVar(&nf.outputFormat, "format", "json", "Output format (json, csv, txt)")
	flag.IntVar(&nf.packetLimit, "c", 0, "Packet count limit (0 = unlimited)")
	flag.DurationVar(&nf.timeout, "t", 30*time.Second, "Capture timeout")
	flag.BoolVar(&nf.verbose, "v", false, "Verbose output")
	flag.Parse()
}

func (nf *NetworkForensics) listInterfaces() error {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return fmt.Errorf("error finding devices: %v", err)
	}

	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║                    XILLEN Network Forensics                ║")
	fmt.Println("║                        v2.0 by @Bengamin_Button            ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println("\nДоступные сетевые интерфейсы:")

	for i, device := range devices {
		fmt.Printf("\n%d. %s\n", i+1, device.Name)
		if device.Description != "" {
			fmt.Printf("   Описание: %s\n", device.Description)
		}
		fmt.Printf("   IP адреса:\n")
		for _, address := range device.Addresses {
			fmt.Printf("     %s\n", address.IP)
		}
	}

	return nil
}

func (nf *NetworkForensics) startCapture() error {
	if nf.interfaceName == "" {
		return fmt.Errorf("необходимо указать интерфейс (-i)")
	}

	handle, err := pcap.OpenLive(nf.interfaceName, 65536, true, nf.timeout)
	if err != nil {
		return fmt.Errorf("ошибка открытия интерфейса %s: %v", nf.interfaceName, err)
	}
	defer handle.Close()

	if nf.filter != "" {
		if err := handle.SetBPFFilter(nf.filter); err != nil {
			return fmt.Errorf("ошибка установки BPF фильтра: %v", err)
		}
	}

	fmt.Printf("🎯 Захват пакетов на интерфейсе: %s\n", nf.interfaceName)
	if nf.filter != "" {
		fmt.Printf("🔍 BPF фильтр: %s\n", nf.filter)
	}
	fmt.Printf("⏱️  Таймаут: %v\n", nf.timeout)
	fmt.Printf("📦 Лимит пакетов: %d\n", nf.packetLimit)
	fmt.Println("\n🚀 Начинаю захват...")

	nf.startTime = time.Now()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	packetCount := 0
	for packet := range packetSource.Packets() {
		nf.processPacket(packet)
		packetCount++

		if nf.verbose {
			fmt.Printf("📦 Пакет %d: %s -> %s (%s)\n",
				packetCount,
				nf.getSourceInfo(packet),
				nf.getDestInfo(packet),
				nf.getProtocolInfo(packet))
		}

		if nf.packetLimit > 0 && packetCount >= nf.packetLimit {
			break
		}
	}

	nf.endTime = time.Now()
	nf.totalPackets = packetCount

	fmt.Printf("\n✅ Захват завершен. Обработано пакетов: %d\n", packetCount)
	return nil
}

func (nf *NetworkForensics) processPacket(packet gopacket.Packet) {
	nf.mutex.Lock()
	defer nf.mutex.Unlock()

	packetInfo := PacketInfo{
		Timestamp: packet.Metadata().Timestamp,
		Length:    packet.Metadata().Length,
	}

	nf.totalBytes += packetInfo.Length

	networkLayer := packet.NetworkLayer()
	if networkLayer != nil {
		switch networkLayer.LayerType() {
		case layers.LayerTypeIPv4:
			ipLayer := networkLayer.(*layers.IPv4)
			packetInfo.SourceIP = ipLayer.SrcIP.String()
			packetInfo.DestIP = ipLayer.DstIP.String()
			packetInfo.TTL = ipLayer.TTL
			packetInfo.Checksum = ipLayer.Checksum
			packetInfo.FragmentID = ipLayer.Id
			packetInfo.FragmentOffset = ipLayer.FragOffset
			packetInfo.MoreFragments = ipLayer.Flags&0x2000 != 0

			nf.updateIPStats(packetInfo.SourceIP)
			nf.updateIPStats(packetInfo.DestIP)

		case layers.LayerTypeIPv6:
			ipLayer := networkLayer.(*layers.IPv6)
			packetInfo.SourceIP = ipLayer.SrcIP.String()
			packetInfo.DestIP = ipLayer.DstIP.String()
			packetInfo.TTL = ipLayer.HopLimit

			nf.updateIPStats(packetInfo.SourceIP)
			nf.updateIPStats(packetInfo.DestIP)
		}
	}

	transportLayer := packet.TransportLayer()
	if transportLayer != nil {
		switch transportLayer.LayerType() {
		case layers.LayerTypeTCP:
			tcpLayer := transportLayer.(*layers.TCP)
			packetInfo.Protocol = "TCP"
			packetInfo.SourcePort = uint16(tcpLayer.SrcPort)
			packetInfo.DestPort = uint16(tcpLayer.DstPort)
			packetInfo.SequenceNum = tcpLayer.Seq
			packetInfo.ACKNum = tcpLayer.Ack
			packetInfo.WindowSize = tcpLayer.Window
			packetInfo.Flags = nf.getTCPFlags(tcpLayer)

			nf.updatePortStats(packetInfo.SourcePort)
			nf.updatePortStats(packetInfo.DestPort)
			nf.updateConnection(packetInfo, "TCP")

		case layers.LayerTypeUDP:
			udpLayer := transportLayer.(*layers.UDP)
			packetInfo.Protocol = "UDP"
			packetInfo.SourcePort = uint16(udpLayer.SrcPort)
			packetInfo.DestPort = uint16(udpLayer.DstPort)
			packetInfo.Checksum = udpLayer.Checksum

			nf.updatePortStats(packetInfo.SourcePort)
			nf.updatePortStats(packetInfo.DestPort)
			nf.updateConnection(packetInfo, "UDP")
		}
	}

	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		packetInfo.Payload = string(applicationLayer.Payload())

		if packetInfo.Protocol == "TCP" && packetInfo.DestPort == 80 {
			nf.parseHTTP(packetInfo)
		} else if packetInfo.Protocol == "UDP" && (packetInfo.DestPort == 53 || packetInfo.SourcePort == 53) {
			nf.parseDNS(packetInfo)
		}
	}

	icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
	if icmpLayer != nil {
		icmp := icmpLayer.(*layers.ICMPv4)
		packetInfo.Protocol = "ICMP"
		packetInfo.ICMPType = icmp.TypeCode.Type()
		packetInfo.ICMPCode = icmp.TypeCode.Code()
		packetInfo.Checksum = icmp.Checksum
	}

	nf.packets = append(nf.packets, packetInfo)
	nf.detectAnomalies(packetInfo)
}

func (nf *NetworkForensics) getSourceInfo(packet gopacket.Packet) string {
	networkLayer := packet.NetworkLayer()
	if networkLayer != nil {
		switch networkLayer.LayerType() {
		case layers.LayerTypeIPv4:
			return networkLayer.(*layers.IPv4).SrcIP.String()
		case layers.LayerTypeIPv6:
			return networkLayer.(*layers.IPv6).SrcIP.String()
		}
	}
	return "Unknown"
}

func (nf *NetworkForensics) getDestInfo(packet gopacket.Packet) string {
	networkLayer := packet.NetworkLayer()
	if networkLayer != nil {
		switch networkLayer.LayerType() {
		case layers.LayerTypeIPv4:
			return networkLayer.(*layers.IPv4).DstIP.String()
		case layers.LayerTypeIPv6:
			return networkLayer.(*layers.IPv6).DstIP.String()
		}
	}
	return "Unknown"
}

func (nf *NetworkForensics) getProtocolInfo(packet gopacket.Packet) string {
	transportLayer := packet.TransportLayer()
	if transportLayer != nil {
		return transportLayer.LayerType().String()
	}
	return "Unknown"
}

func (nf *NetworkForensics) getTCPFlags(tcp *layers.TCP) string {
	flags := []string{}
	if tcp.FIN {
		flags = append(flags, "FIN")
	}
	if tcp.SYN {
		flags = append(flags, "SYN")
	}
	if tcp.RST {
		flags = append(flags, "RST")
	}
	if tcp.PSH {
		flags = append(flags, "PSH")
	}
	if tcp.ACK {
		flags = append(flags, "ACK")
	}
	if tcp.URG {
		flags = append(flags, "URG")
	}
	return strings.Join(flags, ",")
}

func (nf *NetworkForensics) updateIPStats(ip string) {
	nf.ipStats[ip]++
}

func (nf *NetworkForensics) updatePortStats(port uint16) {
	nf.portStats[port]++
}

func (nf *NetworkForensics) updateConnection(packet PacketInfo, protocol string) {
	key := fmt.Sprintf("%s:%d-%s:%d-%s",
		packet.SourceIP, packet.SourcePort,
		packet.DestIP, packet.DestPort, protocol)

	if conn, exists := nf.connections[key]; exists {
		conn.Packets++
		conn.Bytes += packet.Length
		conn.EndTime = packet.Timestamp
	} else {
		nf.connections[key] = &Connection{
			SourceIP:   packet.SourceIP,
			DestIP:     packet.DestIP,
			SourcePort: packet.SourcePort,
			DestPort:   packet.DestPort,
			Protocol:   protocol,
			StartTime:  packet.Timestamp,
			EndTime:    packet.Timestamp,
			Packets:    1,
			Bytes:      packet.Length,
			Status:     "Active",
		}
	}
}

func (nf *NetworkForensics) parseHTTP(packet PacketInfo) {
	payload := packet.Payload
	if strings.HasPrefix(payload, "GET ") || strings.HasPrefix(payload, "POST ") ||
		strings.HasPrefix(payload, "PUT ") || strings.HasPrefix(payload, "DELETE ") {

		lines := strings.Split(payload, "\n")
		if len(lines) > 0 {
			parts := strings.Fields(lines[0])
			if len(parts) >= 2 {
				packet.HTTPMethod = parts[0]
				packet.HTTPPath = parts[1]
			}
		}

		for _, line := range lines {
			if strings.HasPrefix(line, "Host: ") {
				packet.HTTPHost = strings.TrimPrefix(line, "Host: ")
			}
			if strings.HasPrefix(line, "User-Agent: ") {
				packet.HTTPUserAgent = strings.TrimPrefix(line, "User-Agent: ")
			}
		}
	}
}

func (nf *NetworkForensics) parseDNS(packet PacketInfo) {
	if packet.DestPort == 53 {
		packet.DNSQuery = "DNS Query"
	} else if packet.SourcePort == 53 {
		packet.DNSResponse = "DNS Response"
	}
}

func (nf *NetworkForensics) detectAnomalies(packet PacketInfo) {
	if packet.Protocol == "TCP" {
		if packet.SourcePort == 22 || packet.DestPort == 22 {
			nf.addAnomaly("SSH_TRAFFIC", "Обнаружен SSH трафик", "LOW", packet.Timestamp)
		}
		if packet.SourcePort == 3389 || packet.DestPort == 3389 {
			nf.addAnomaly("RDP_TRAFFIC", "Обнаружен RDP трафик", "MEDIUM", packet.Timestamp)
		}
		if packet.SourcePort == 445 || packet.DestPort == 445 {
			nf.addAnomaly("SMB_TRAFFIC", "Обнаружен SMB трафик", "MEDIUM", packet.Timestamp)
		}
	}

	if packet.Protocol == "ICMP" {
		if packet.ICMPType == 8 {
			nf.addAnomaly("ICMP_PING", "Обнаружен ICMP ping", "LOW", packet.Timestamp)
		}
	}

	if packet.FragmentOffset > 0 {
		nf.addAnomaly("FRAGMENTED_PACKET", "Обнаружен фрагментированный пакет", "MEDIUM", packet.Timestamp)
	}
}

func (nf *NetworkForensics) addAnomaly(anomalyType, description, severity string, timestamp time.Time) {
	anomaly := fmt.Sprintf("[%s] %s - %s (%s)",
		severity, anomalyType, description, timestamp.Format("15:04:05"))
	nf.anomalies = append(nf.anomalies, anomaly)
}

func (nf *NetworkForensics) generateReport() *ForensicReport {
	nf.mutex.RLock()
	defer nf.mutex.RUnlock()

	report := &ForensicReport{}

	report.CaptureInfo.Interface = nf.interfaceName
	report.CaptureInfo.StartTime = nf.startTime
	report.CaptureInfo.EndTime = nf.endTime
	report.CaptureInfo.TotalPackets = nf.totalPackets
	report.CaptureInfo.TotalBytes = nf.totalBytes
	report.CaptureInfo.Duration = nf.endTime.Sub(nf.startTime).String()

	report.NetworkStats.UniqueIPs = len(nf.ipStats)
	report.NetworkStats.UniquePorts = len(nf.portStats)

	tcpCount, udpCount, icmpCount, httpCount, dnsCount := 0, 0, 0, 0, 0
	for _, packet := range nf.packets {
		switch packet.Protocol {
		case "TCP":
			tcpCount++
		case "UDP":
			udpCount++
		case "ICMP":
			icmpCount++
		}
		if packet.HTTPMethod != "" {
			httpCount++
		}
		if packet.DNSQuery != "" || packet.DNSResponse != "" {
			dnsCount++
		}
	}

	report.NetworkStats.TCPConnections = tcpCount
	report.NetworkStats.UDPConnections = udpCount
	report.NetworkStats.ICMPPackets = icmpCount
	report.NetworkStats.HTTPRequests = httpCount
	report.NetworkStats.DNSQueries = dnsCount

	nf.addTopTalkers(report)
	nf.addTopPorts(report)
	nf.addAnomaliesToReport(report)
	nf.addConnectionsToReport(report)

	return report
}

func (nf *NetworkForensics) addTopTalkers(report *ForensicReport) {
	type ipStat struct {
		ip      string
		packets int
		bytes   int
	}

	var stats []ipStat
	for ip, count := range nf.ipStats {
		bytes := 0
		for _, packet := range nf.packets {
			if packet.SourceIP == ip || packet.DestIP == ip {
				bytes += packet.Length
			}
		}
		stats = append(stats, ipStat{ip, count, bytes})
	}

	for i := 0; i < 10 && i < len(stats); i++ {
		report.TopTalkers = append(report.TopTalkers, struct {
			IP      string `json:"ip"`
			Packets int    `json:"packets"`
			Bytes   int    `json:"bytes"`
		}{
			IP:      stats[i].ip,
			Packets: stats[i].packets,
			Bytes:   stats[i].bytes,
		})
	}
}

func (nf *NetworkForensics) addTopPorts(report *ForensicReport) {
	type portStat struct {
		port    uint16
		packets int
		bytes   int
	}

	var stats []portStat
	for port, count := range nf.portStats {
		bytes := 0
		for _, packet := range nf.packets {
			if packet.SourcePort == port || packet.DestPort == port {
				bytes += packet.Length
			}
		}
		stats = append(stats, portStat{port, count, bytes})
	}

	for i := 0; i < 10 && i < len(stats); i++ {
		report.TopPorts = append(report.TopPorts, struct {
			Port    uint16 `json:"port"`
			Packets int    `json:"packets"`
			Bytes   int    `json:"bytes"`
		}{
			Port:    stats[i].port,
			Packets: stats[i].packets,
			Bytes:   stats[i].bytes,
		})
	}
}

func (nf *NetworkForensics) addAnomaliesToReport(report *ForensicReport) {
	for _, anomaly := range nf.anomalies {
		parts := strings.SplitN(anomaly, " ", 4)
		if len(parts) >= 4 {
			severity := strings.Trim(parts[0], "[]")
			anomalyType := parts[1]
			description := parts[2]
			timestamp := parts[3]

			report.Anomalies = append(report.Anomalies, struct {
				Type        string `json:"type"`
				Description string `json:"description"`
				Severity    string `json:"severity"`
				Timestamp   string `json:"timestamp"`
			}{
				Type:        anomalyType,
				Description: description,
				Severity:    severity,
				Timestamp:   timestamp,
			})
		}
	}
}

func (nf *NetworkForensics) addConnectionsToReport(report *ForensicReport) {
	for _, conn := range nf.connections {
		report.Connections = append(report.Connections, *conn)
	}
}

func (nf *NetworkForensics) saveReport(report *ForensicReport) error {
	switch nf.outputFormat {
	case "json":
		return nf.saveJSON(report)
	case "csv":
		return nf.saveCSV(report)
	case "txt":
		return nf.saveTXT(report)
	default:
		return fmt.Errorf("неподдерживаемый формат: %s", nf.outputFormat)
	}
}

func (nf *NetworkForensics) saveJSON(report *ForensicReport) error {
	filename := nf.outputFile + ".json"
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func (nf *NetworkForensics) saveCSV(report *ForensicReport) error {
	filename := nf.outputFile + ".csv"
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	headers := []string{"Timestamp", "Source IP", "Dest IP", "Source Port", "Dest Port", "Protocol", "Length", "Flags"}
	if err := writer.Write(headers); err != nil {
		return err
	}

	for _, packet := range nf.packets {
		row := []string{
			packet.Timestamp.Format("2006-01-02 15:04:05"),
			packet.SourceIP,
			packet.DestIP,
			strconv.Itoa(int(packet.SourcePort)),
			strconv.Itoa(int(packet.DestPort)),
			packet.Protocol,
			strconv.Itoa(packet.Length),
			packet.Flags,
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}

func (nf *NetworkForensics) saveTXT(report *ForensicReport) error {
	filename := nf.outputFile + ".txt"
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)

	fmt.Fprintf(writer, "╔══════════════════════════════════════════════════════════════╗\n")
	fmt.Fprintf(writer, "║                    XILLEN Network Forensics                ║\n")
	fmt.Fprintf(writer, "║                        v2.0 by @Bengamin_Button            ║\n")
	fmt.Fprintf(writer, "╚══════════════════════════════════════════════════════════════╝\n\n")

	fmt.Fprintf(writer, "📊 ОТЧЕТ ПО СЕТЕВОЙ КРИМИНАЛИСТИКЕ\n")
	fmt.Fprintf(writer, "=====================================\n\n")

	fmt.Fprintf(writer, "🔍 ИНФОРМАЦИЯ О ЗАХВАТЕ\n")
	fmt.Fprintf(writer, "Интерфейс: %s\n", report.CaptureInfo.Interface)
	fmt.Fprintf(writer, "Время начала: %s\n", report.CaptureInfo.StartTime.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(writer, "Время окончания: %s\n", report.CaptureInfo.EndTime.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(writer, "Длительность: %s\n", report.CaptureInfo.Duration)
	fmt.Fprintf(writer, "Всего пакетов: %d\n", report.CaptureInfo.TotalPackets)
	fmt.Fprintf(writer, "Всего байт: %d\n\n", report.CaptureInfo.TotalBytes)

	fmt.Fprintf(writer, "📈 СТАТИСТИКА СЕТИ\n")
	fmt.Fprintf(writer, "Уникальных IP: %d\n", report.NetworkStats.UniqueIPs)
	fmt.Fprintf(writer, "Уникальных портов: %d\n", report.NetworkStats.UniquePorts)
	fmt.Fprintf(writer, "TCP соединений: %d\n", report.NetworkStats.TCPConnections)
	fmt.Fprintf(writer, "UDP соединений: %d\n", report.NetworkStats.UDPConnections)
	fmt.Fprintf(writer, "ICMP пакетов: %d\n", report.NetworkStats.ICMPPackets)
	fmt.Fprintf(writer, "HTTP запросов: %d\n", report.NetworkStats.HTTPRequests)
	fmt.Fprintf(writer, "DNS запросов: %d\n\n", report.NetworkStats.DNSQueries)

	if len(report.TopTalkers) > 0 {
		fmt.Fprintf(writer, "🏆 ТОП IP АДРЕСОВ\n")
		for i, talker := range report.TopTalkers {
			fmt.Fprintf(writer, "%d. %s - %d пакетов, %d байт\n",
				i+1, talker.IP, talker.Packets, talker.Bytes)
		}
		fmt.Fprintf(writer, "\n")
	}

	if len(report.TopPorts) > 0 {
		fmt.Fprintf(writer, "🔌 ТОП ПОРТОВ\n")
		for i, port := range report.TopPorts {
			fmt.Fprintf(writer, "%d. Порт %d - %d пакетов, %d байт\n",
				i+1, port.Port, port.Packets, port.Bytes)
		}
		fmt.Fprintf(writer, "\n")
	}

	if len(report.Anomalies) > 0 {
		fmt.Fprintf(writer, "⚠️  АНОМАЛИИ\n")
		for _, anomaly := range report.Anomalies {
			fmt.Fprintf(writer, "[%s] %s - %s (%s)\n",
				anomaly.Severity, anomaly.Type, anomaly.Description, anomaly.Timestamp)
		}
		fmt.Fprintf(writer, "\n")
	}

	return writer.Flush()
}

func main() {
	forensics := NewNetworkForensics()
	forensics.parseFlags()

	if len(flag.Args()) == 0 {
		if err := forensics.listInterfaces(); err != nil {
			log.Fatal(err)
		}
		return
	}

	if err := forensics.startCapture(); err != nil {
		log.Fatal(err)
	}

	report := forensics.generateReport()

	if err := forensics.saveReport(report); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("📄 Отчет сохранен в файл: %s.%s\n", forensics.outputFile, forensics.outputFormat)
	fmt.Println("\n✅ Анализ завершен успешно!")
}

