## Python Network Intrusion Detection System (NIDS) with Deep Packet Inspection

### Project Overview

This project is a modular Python-based Network Intrusion Detection System (NIDS) built using Scapy for packet parsing and analysis.

The system processes PCAP files, tracks TCP connections, performs basic deep packet inspection (DPI), extracts TLS Server Name Indication (SNI) values from ClientHello messages, detects blacklisted domains and potential port-scanning behavior, and assigns a configurable risk score per connection.

The final output is a structured, human-readable security report, with optional JSON export for further automated processing.

The goal of this project is to implement and understand core IDS detection concepts in a clean and extensible architecture rather than replicate full-scale enterprise security products.

---

### Architecture Overview

The codebase is modular and designed for clarity and extensibility.

- `main.py` – CLI entrypoint and orchestration layer. Coordinates packet parsing, detection modules, risk scoring, and report generation.
- `pcap_reader.py` – Wrapper around Scapy’s `rdpcap()` for loading packets from PCAP files.
- `connection_tracker.py` – Tracks TCP connections using the 4-tuple `(src_ip, src_port, dst_ip, dst_port)` and maintains packet and byte counts.
- `dpi_engine.py` – Performs payload inspection by scanning `Raw` data for configurable suspicious keywords.
- `sni_extractor.py` – Extracts TLS SNI values from ClientHello messages by parsing TLS record structures directly from raw bytes.
- `rule_manager.py` – Centralizes detection policies from `config.py` such as suspicious keywords, blacklisted domains, and thresholds.
- `anomaly_detector.py` – Implements basic behavioral analysis, currently focused on detecting potential port-scanning behavior.
- `risk_scorer.py` – Maintains a cumulative risk score per connection and maps it to LOW, MEDIUM, or HIGH levels.
- `config.py` – Stores all configurable parameters including keyword lists, domain blacklists, port-scan thresholds, and risk thresholds.

---

### Data Flow

1. `main.py` reads packets from a PCAP file.
2. Packets are grouped into TCP connections using `ConnectionTracker`.
3. `DPIEngine` inspects payload data for suspicious keywords.
4. `SNIExtractor` attempts to extract TLS SNI values from ClientHello packets.
5. `RuleManager` checks extracted SNI values against a configurable blacklist.
6. `AnomalyDetector` tracks unique destination ports per source IP to detect possible port scans.
7. `RiskScorer` aggregates detection signals into a per-connection risk score and level.
8. A final report is printed and optionally exported to JSON.

---

### Feature List

- **PCAP Ingestion**
  - Loads packet captures using Scapy.
  - Supports offline analysis of recorded network traffic.

- **TCP Connection Tracking**
  - Tracks connections using 4-tuple identification.
  - Maintains packet count and byte count per connection.

- **Basic Deep Packet Inspection (DPI)**
  - Inspects `Raw` payload data for configurable suspicious keywords.
  - Keyword list is defined in `config.py`.

- **TLS SNI Extraction**
  - Parses TLS ClientHello messages to extract the Server Name Indication (SNI).
  - Enables visibility into encrypted traffic destinations without decrypting payloads.

- **Blacklist-Based Domain Detection**
  - Compares extracted SNI values against a configurable blacklist.
  - Increases risk score when blacklisted domains are detected.

- **Port Scan Detection**
  - Tracks unique destination ports contacted by each source IP.
  - Raises an alert when the number exceeds `PORT_SCAN_THRESHOLD`.

- **Dynamic Risk Scoring**
  - Assigns cumulative risk scores based on:
    - Suspicious payload keywords
    - Blacklisted domain matches
    - Port scan behavior
  - Maps scores to LOW, MEDIUM, or HIGH levels using configurable thresholds.

- **Structured Reporting**
  - Generates a human-readable console report including:
    - Total packets and connections
    - Port scan alerts
    - Per-connection risk assessment
  - Optional JSON export for programmatic consumption.

---

### Why This Project

This project demonstrates practical understanding of:

- Network traffic analysis using PCAP files
- TCP connection tracking
- Basic deep packet inspection
- Behavioral anomaly detection
- Risk scoring and alert prioritization

It focuses on implementing core IDS concepts in a modular and understandable way.

### Installation

#### Prerequisites
- Python 3.10+
- A PCAP file for analysis

#### Setup

```bash
python -m venv .venv
.venv\Scripts\activate      # Windows
# source .venv/bin/activate # Linux/macOS

pip install -r requirements.txt

```

---

### Usage

Run the analyzer from the project directory:

```bash
python main.py path\to\capture.pcap
```

Optional arguments:

- `-o / --json-out <file>`  
  Export the report to a JSON file.

- `-v / --verbose`  
  Enable detailed logging during analysis.

Example:

```bash
python main.py samples\traffic.pcap -o report.json -v
```

---

### Example Output

Example console report:

```
================================================================================
PROCESSING REPORT
================================================================================
Total Packets: 628
TCP Packets: 435
UDP Packets: 191
Connections: 35

================================================================================
PORT SCAN ALERTS
================================================================================
Source 192.168.29.220 contacted 3 unique destination ports (possible port scan)

================================================================================
PER-CONNECTION RISK ASSESSMENT
================================================================================
SRC                   DST                     PKTS   BYTES   RISK   LEVEL
192.168.29.220:56063  142.251.220.110:50        1      66      3     LOW
```

---

### Future Improvements

- Add protocol-aware parsing for HTTP and DNS.
- Enhance anomaly detection using time-based thresholds.
- Support live packet capture in addition to PCAP analysis.
- Add unit tests and CI integration.

---