# Network Traffic Behavioral Analyzer

## Overview
The Network Traffic Behavioral Analyzer is a cybersecurity tool designed to identify network anomalies through behavioral analysis rather than simple signatures. By analyzing traffic flows, it detects potential Command & Control (C2) beaconing and data exfiltration attempts.

## Key Features
- **Traffic Capture**: Analyze live network traffic or process existing PCAP files using Scapy.
- **Behavioral Detection**: 
    - **C2 Beaconing**: Identifies rhythmic traffic patterns common in malware communications.
    - **Data Exfiltration**: Detects unusual outbound data volumes to external IPs.
- **AI-Powered Insights**: Integrates with LLMs to provide human-readable summaries of suspicious traffic flows.
- **Visual Analytics**: Generates interactive visualizations of traffic volume and protocol distribution using Plotly.

## Installation
1. Clone the repository.
2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. (Optional) Set up your `.env` file with an OpenAI API key for AI summarization.

## Usage
### Analyze a PCAP File
```bash
python main.py --pcap path/to/your/file.pcap
```

### Live Traffic Capture
```bash
python main.py --interface eth0 --count 500
```

## Project Structure
- `src/analyzer.py`: Handles packet capture and feature extraction.
- `src/detectors.py`: Contains anomaly detection logic for beaconing and exfiltration.
- `src/ai_summarizer.py`: Provides LLM-based summarization of detected threats.
- `src/visualizer.py`: Generates traffic visualizations.
- `main.py`: The main entry point for the application.

## Portfolio Context
This project was developed to demonstrate a deep understanding of network protocols and the ability to build custom security logic for threat detection. It bridges the gap between raw packet analysis and actionable security intelligence.
