import scapy.all as scapy
import pandas as pd
from collections import defaultdict
import os

class NetworkAnalyzer:
    def __init__(self, target=None):
        self.target = target
        self.flows = defaultdict(list)

    def process_pcap(self, file_path):
        """Read packets from a PCAP file."""
        if not os.path.exists(file_path):
            print(f"Error: File {file_path} not found.")
            return None
        
        print(f"Processing PCAP: {file_path}...")
        packets = scapy.rdpcap(file_path)
        return self._extract_features(packets)

    def live_capture(self, interface, count=100):
        """Capture live traffic."""
        print(f"Starting live capture on {interface} for {count} packets...")
        packets = scapy.sniff(iface=interface, count=count)
        return self._extract_features(packets)

    def _extract_features(self, packets):
        """Extract key metrics from captured packets."""
        data = []
        for pkt in packets:
            if pkt.haslayer(scapy.IP):
                flow_id = tuple(sorted([pkt[scapy.IP].src, pkt[scapy.IP].dst]))
                
                # Basic features
                packet_info = {
                    'timestamp': float(pkt.time),
                    'src': pkt[scapy.IP].src,
                    'dst': pkt[scapy.IP].dst,
                    'size': len(pkt),
                    'proto': pkt[scapy.IP].proto
                }
                
                if pkt.haslayer(scapy.TCP):
                    packet_info['sport'] = pkt[scapy.TCP].sport
                    packet_info['dport'] = pkt[scapy.TCP].dport
                elif pkt.haslayer(scapy.UDP):
                    packet_info['sport'] = pkt[scapy.UDP].sport
                    packet_info['dport'] = pkt[scapy.UDP].dport
                
                data.append(packet_info)
        
        df = pd.DataFrame(data)
        if not df.empty:
            df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s')
        return df

if __name__ == "__main__":
    analyzer = NetworkAnalyzer()
    # Example usage:
    # df = analyzer.process_pcap('data/sample.pcap')
    # print(df.head())
