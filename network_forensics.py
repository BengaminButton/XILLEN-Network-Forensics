#!/usr/bin/env python3
import argparse
import sys
import os
import pyshark
import json
import time
from datetime import datetime
from collections import defaultdict

class NetworkForensics:
    def __init__(self):
        self.pcap_data = None
        self.connections = defaultdict(list)
        self.protocols = defaultdict(int)
        self.suspicious_activity = []
        self.timeline = []
        
    def load_pcap(self, pcap_file):
        """Загрузка PCAP файла"""
        if not os.path.exists(pcap_file):
            print(f"[-] PCAP file not found: {pcap_file}")
            return False
        
        try:
            print(f"[+] Loading PCAP file: {pcap_file}")
            self.pcap_data = pyshark.FileCapture(pcap_file)
            print(f"[+] PCAP loaded successfully")
            return True
        except Exception as e:
            print(f"[-] Error loading PCAP: {e}")
            return False
    
    def analyze_connections(self):
        """Анализ сетевых соединений"""
        print("[+] Analyzing network connections...")
        
        connection_count = 0
        
        for packet in self.pcap_data:
            try:
                if hasattr(packet, 'ip'):
                    src_ip = packet.ip.src
                    dst_ip = packet.ip.dst
                    
                    if hasattr(packet, 'tcp'):
                        src_port = packet.tcp.srcport
                        dst_port = packet.tcp.dstport
                        protocol = 'TCP'
                    elif hasattr(packet, 'udp'):
                        src_port = packet.udp.srcport
                        dst_port = packet.udp.dstport
                        protocol = 'UDP'
                    else:
                        continue
                    
                    connection_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
                    
                    connection_info = {
                        'src_ip': src_ip,
                        'src_port': src_port,
                        'dst_ip': dst_ip,
                        'dst_port': dst_port,
                        'protocol': protocol,
                        'timestamp': packet.sniff_timestamp,
                        'length': packet.length,
                        'flags': getattr(packet.tcp, 'flags', '') if protocol == 'TCP' else ''
                    }
                    
                    self.connections[connection_key].append(connection_info)
                    connection_count += 1
                    
                    if connection_count % 1000 == 0:
                        print(f"    Processed {connection_count} packets...")
                        
            except Exception as e:
                continue
        
        print(f"[+] Analysis completed. Total connections: {len(self.connections)}")
    
    def analyze_protocols(self):
        """Анализ протоколов"""
        print("[+] Analyzing protocols...")
        
        for connection_key, packets in self.connections.items():
            for packet in packets:
                protocol = packet['protocol']
                self.protocols[protocol] += 1
        
        print("[+] Protocol analysis completed")
    
    def detect_suspicious_activity(self):
        """Обнаружение подозрительной активности"""
        print("[+] Detecting suspicious activity...")
        
        for connection_key, packets in self.connections.items():
            connection_info = packets[0]
            
            # Подозрительные порты
            suspicious_ports = [22, 23, 3389, 5900, 1433, 3306, 5432]
            if int(connection_info['dst_port']) in suspicious_ports:
                self.suspicious_activity.append({
                    'type': 'Suspicious Port',
                    'connection': connection_key,
                    'details': f"Connection to port {connection_info['dst_port']}",
                    'risk': 'Medium'
                })
            
            # Большое количество пакетов
            if len(packets) > 1000:
                self.suspicious_activity.append({
                    'type': 'High Packet Count',
                    'connection': connection_key,
                    'details': f"{len(packets)} packets in connection",
                    'risk': 'Low'
                })
            
            # Необычные флаги TCP
            if connection_info['protocol'] == 'TCP':
                flags = connection_info['flags']
                if 'RST' in flags and 'SYN' in flags:
                    self.suspicious_activity.append({
                        'type': 'Unusual TCP Flags',
                        'connection': connection_key,
                        'details': f"TCP flags: {flags}",
                        'risk': 'Medium'
                    })
        
        print(f"[+] Suspicious activity detection completed. Found {len(self.suspicious_activity)} items")
    
    def build_timeline(self):
        """Построение временной шкалы"""
        print("[+] Building timeline...")
        
        for connection_key, packets in self.connections.items():
            for packet in packets:
                timestamp = float(packet['timestamp'])
                dt = datetime.fromtimestamp(timestamp)
                
                timeline_entry = {
                    'timestamp': dt.isoformat(),
                    'connection': connection_key,
                    'event': f"{packet['protocol']} packet",
                    'length': packet['length'],
                    'src': f"{packet['src_ip']}:{packet['src_port']}",
                    'dst': f"{packet['dst_ip']}:{packet['dst_port']}"
                }
                
                self.timeline.append(timeline_entry)
        
        self.timeline.sort(key=lambda x: x['timestamp'])
        print(f"[+] Timeline built with {len(self.timeline)} events")
    
    def analyze_payload_patterns(self):
        """Анализ паттернов полезной нагрузки"""
        print("[+] Analyzing payload patterns...")
        
        payload_patterns = {
            'http_requests': 0,
            'dns_queries': 0,
            'encrypted_traffic': 0,
            'plain_text': 0
        }
        
        for connection_key, packets in self.connections.items():
            for packet in packets:
                if hasattr(packet, 'data'):
                    data = str(packet.data)
                    
                    if 'GET ' in data or 'POST ' in data or 'HTTP/' in data:
                        payload_patterns['http_requests'] += 1
                    elif 'DNS' in data:
                        payload_patterns['dns_queries'] += 1
                    elif len(data) > 100 and not any(char.isprintable() for char in data[:100]):
                        payload_patterns['encrypted_traffic'] += 1
                    else:
                        payload_patterns['plain_text'] += 1
        
        print("[+] Payload pattern analysis completed")
        return payload_patterns
    
    def generate_statistics(self):
        """Генерация статистики"""
        print("[+] Generating statistics...")
        
        stats = {
            'total_connections': len(self.connections),
            'total_packets': sum(len(packets) for packets in self.connections.values()),
            'protocols': dict(self.protocols),
            'unique_ips': len(set(
                ip for packets in self.connections.values() 
                for packet in packets 
                for ip in [packet['src_ip'], packet['dst_ip']]
            )),
            'unique_ports': len(set(
                port for packets in self.connections.values() 
                for packet in packets 
                for port in [packet['src_port'], packet['dst_port']]
            )),
            'suspicious_activities': len(self.suspicious_activity),
            'timeline_events': len(self.timeline)
        }
        
        return stats
    
    def save_results(self, output_file):
        """Сохранение результатов"""
        try:
            results = {
                'statistics': self.generate_statistics(),
                'suspicious_activity': self.suspicious_activity,
                'timeline': self.timeline[:1000],  # Ограничиваем для файла
                'connections_summary': {
                    key: {
                        'packet_count': len(packets),
                        'first_seen': packets[0]['timestamp'],
                        'last_seen': packets[-1]['timestamp'],
                        'total_bytes': sum(int(p['length']) for p in packets)
                    }
                    for key, packets in list(self.connections.items())[:100]  # Ограничиваем
                }
            }
            
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            
            print(f"[+] Results saved to {output_file}")
            
        except Exception as e:
            print(f"[-] Error saving results: {e}")
    
    def print_summary(self):
        """Вывод сводки"""
        print("\n=== NETWORK FORENSICS SUMMARY ===")
        
        stats = self.generate_statistics()
        
        print(f"Total connections: {stats['total_connections']}")
        print(f"Total packets: {stats['total_packets']}")
        print(f"Unique IPs: {stats['unique_ips']}")
        print(f"Unique ports: {stats['unique_ports']}")
        print(f"Suspicious activities: {stats['suspicious_activities']}")
        print(f"Timeline events: {stats['timeline_events']}")
        
        print("\nProtocols:")
        for protocol, count in stats['protocols'].items():
            print(f"  {protocol}: {count}")
        
        if self.suspicious_activity:
            print(f"\nTop suspicious activities:")
            for activity in self.suspicious_activity[:5]:
                print(f"  [{activity['risk']}] {activity['type']}: {activity['details']}")

def main():
    parser = argparse.ArgumentParser(description='XILLEN Network Forensics Tool')
    parser.add_argument('pcap_file', help='PCAP file to analyze')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('--connections', action='store_true', help='Analyze connections')
    parser.add_argument('--protocols', action='store_true', help='Analyze protocols')
    parser.add_argument('--suspicious', action='store_true', help='Detect suspicious activity')
    parser.add_argument('--timeline', action='store_true', help='Build timeline')
    
    args = parser.parse_args()
    
    forensics = NetworkForensics()
    
    if not forensics.load_pcap(args.pcap_file):
        sys.exit(1)
    
    print(f"[+] Starting XILLEN Network Forensics Analysis")
    print(f"[+] PCAP file: {args.pcap_file}")
    
    start_time = time.time()
    
    if args.connections or not any([args.connections, args.protocols, args.suspicious, args.timeline]):
        forensics.analyze_connections()
    
    if args.protocols or not any([args.connections, args.protocols, args.suspicious, args.timeline]):
        forensics.analyze_protocols()
    
    if args.suspicious or not any([args.connections, args.protocols, args.suspicious, args.timeline]):
        forensics.detect_suspicious_activity()
    
    if args.timeline or not any([args.connections, args.protocols, args.suspicious, args.timeline]):
        forensics.build_timeline()
    
    payload_patterns = forensics.analyze_payload_patterns()
    
    total_time = time.time() - start_time
    
    print(f"\n[+] Analysis completed in {total_time:.2f} seconds")
    
    forensics.print_summary()
    
    if args.output:
        forensics.save_results(args.output)

if __name__ == "__main__":
    main()
