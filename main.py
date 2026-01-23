import argparse
import os
from src.analyzer import NetworkAnalyzer
from src.detectors import AnomalyDetector
from src.ai_summarizer import AISummarizer
from src.visualizer import Visualizer

def main():
    parser = argparse.ArgumentParser(description="Network Traffic Behavioral Analyzer")
    parser.add_argument("--pcap", type=str, help="Path to PCAP file for analysis")
    parser.add_argument("--interface", type=str, help="Interface for live capture (e.g., eth0, wlan0)")
    parser.add_argument("--count", type=int, default=100, help="Number of packets to capture in live mode")
    parser.add_argument("--save-pcap", type=str, help="Save captured packets to PCAP file for Wireshark analysis")
    
    args = parser.parse_args()

    analyzer = NetworkAnalyzer()
    df = None

    if args.pcap:
        df = analyzer.process_pcap(args.pcap)
    elif args.interface:
        df = analyzer.live_capture(args.interface, args.count, save_pcap=args.save_pcap)
    else:
        print("Please provide either --pcap or --interface. Use --help for usage.")
        return

    if df is not None and not df.empty:
        # 1. Feature Extraction (Already done in analyzer)
        print(f"\n[+] Extracted {len(df)} packets with features.")
        print(df[['timestamp', 'src', 'dst', 'size', 'proto']].head())

        # 2. Anomaly Detection
        detector = AnomalyDetector(df)
        beacon_anomalies = detector.detect_beaconing()
        exfil_anomalies = detector.detect_exfiltration()
        
        all_anomalies = beacon_anomalies + exfil_anomalies
        
        print(f"\n[+] Detection Results: Found {len(all_anomalies)} anomalies.")
        for anomaly in all_anomalies:
            print(f"    - {anomaly['type']}: {anomaly['src']} -> {anomaly['dst']}")

        # 3. AI Summarization
        summarizer = AISummarizer()
        summary = summarizer.summarize_anomalies(all_anomalies)
        print(f"\n[+] AI Summary:\n{summary}")

        # 4. Visualization
        visualizer = Visualizer(df)
        visualizer.plot_traffic_volume()
        visualizer.plot_protocol_distribution()
    else:
        print("[-] No traffic data found or processed.")

if __name__ == "__main__":
    main()
