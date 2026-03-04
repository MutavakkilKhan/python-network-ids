from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Any, Dict, List

import config
from anomaly_detector import AnomalyDetector
from connection_tracker import ConnectionTracker, ConnectionKey
from dpi_engine import DPIEngine
from pcap_reader import read_pcap
from risk_scorer import RiskScorer
from rule_manager import RuleManager
from sni_extractor import SNIExtractor


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Advanced Python Packet Analyzer with DPI and Behavioral IDS Features",
    )
    parser.add_argument(
        "pcap",
        help="Path to the PCAP file to analyze.",
    )
    parser.add_argument(
        "-o",
        "--json-out",
        dest="json_out",
        help="Optional path to write the final report as JSON.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose logging.",
    )
    return parser


def configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )


def analyze_pcap(pcap_path: Path, json_out: Path | None = None) -> Dict[str, Any]:
    logger = logging.getLogger(__name__)
    logger.info("Loading rules and configuration.")

    rules = RuleManager.from_module(config)
    dpi = DPIEngine(rules.suspicious_keywords)
    tracker = ConnectionTracker()
    anomaly = AnomalyDetector(rules.port_scan_threshold)
    risk_scorer = RiskScorer(rules)
    sni_extractor = SNIExtractor()

    logger.info("Reading PCAP file: %s", pcap_path)
    packets = read_pcap(str(pcap_path))
    logger.info("Loaded %d packets.", len(packets))

    total_bytes = 0
    tcp_packets = 0
    udp_packets = 0

    for idx, packet in enumerate(packets):
        try:
            total_bytes += int(len(packet))
        except Exception:
            pass

        if packet.haslayer("TCP"):
            tcp_packets += 1
        if packet.haslayer("UDP"):
            udp_packets += 1

        key: ConnectionKey | None = tracker.add_packet(packet, index=idx)
        anomaly.observe_packet(packet)

        # DPI: suspicious payload inspection
        matches = dpi.inspect_packet(packet)
        if key is not None and matches:
            logger.debug("Suspicious payload on connection %s: %s", key, matches)
            risk_scorer.add_suspicious_payload(key, matches)

        # TLS SNI extraction and blacklist detection
        sni = sni_extractor.extract_sni(packet)
        if key is not None and sni:
            logger.debug("Extracted SNI '%s' for connection %s", sni, key)
            if rules.is_domain_blacklisted(sni):
                logger.info("Blacklisted domain detected: %s", sni)
                risk_scorer.add_blacklisted_domain(key, sni)

    # Apply port-scan-based risk adjustments
    logger.info("Evaluating behavioral anomalies (e.g., port scanning).")
    suspicious_sources = anomaly.suspicious_sources
    for key, stats in tracker.connections.items():
        if stats.src_ip in suspicious_sources:
            risk_scorer.add_port_scan_flag(key)

    # Build connection summaries
    connection_reports: List[Dict[str, Any]] = []
    for key, stats in tracker.connections.items():
        connection_reports.append(risk_scorer.summarize_connection(key, stats))

    # Build high-level risk summary
    overall = {
        "total_packets": len(packets),
        "total_connections": len(tracker.connections),
        "total_bytes": total_bytes,
        "tcp_packets": tcp_packets,
        "udp_packets": udp_packets,
        "port_scan_alerts": [
            {
                "source_ip": alert.source_ip,
                "unique_ports": alert.unique_ports,
            }
            for alert in anomaly.alerts
        ],
    }

    # Risk distribution
    risk_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
    for conn in connection_reports:
        level = str(conn["risk_level"])
        risk_counts[level] = risk_counts.get(level, 0) + 1
    overall["risk_distribution"] = risk_counts

    report: Dict[str, Any] = {
        "summary": overall,
        "connections": connection_reports,
    }

    if json_out is not None:
        logger.info("Writing JSON report to %s", json_out)
        with json_out.open("w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

    return report


def print_human_report(report: Dict[str, Any]) -> None:
    summary = report["summary"]
    connections = sorted(
        report["connections"],
        key=lambda c: int(c.get("risk_score", 0)),
        reverse=True,
    )

    width = 80

    def line(char: str = "=") -> None:
        print(char * width)

    def section_title(title: str) -> None:
        line("=")
        print(title.center(width))
        line("=")

    print()
    section_title("PROCESSING REPORT")

    # High-level packet stats
    print(f"{'Total Packets:':<20}{summary.get('total_packets', 0):>10}")
    print(f"{'Total Bytes:':<20}{summary.get('total_bytes', 0):>10}")
    print(f"{'TCP Packets:':<20}{summary.get('tcp_packets', 0):>10}")
    print(f"{'UDP Packets:':<20}{summary.get('udp_packets', 0):>10}")
    print(f"{'Connections:':<20}{summary.get('total_connections', 0):>10}")

    # Risk distribution
    dist = summary.get("risk_distribution", {})
    print()
    print("Risk Levels:")
    print(
        f"  LOW={dist.get('LOW', 0)}  "
        f"MEDIUM={dist.get('MEDIUM', 0)}  "
        f"HIGH={dist.get('HIGH', 0)}"
    )

    # Port scan section
    print()
    section_title("PORT SCAN ALERTS")
    alerts = summary.get("port_scan_alerts", [])
    if not alerts:
        print("No port scan behavior detected.")
    else:
        for alert in alerts:
            print(
                f"Source {alert['source_ip']} contacted "
                f"{alert['unique_ports']} unique destination ports "
                f"(possible port scan)"
            )

    # Per-connection table
    print()
    section_title("PER-CONNECTION RISK ASSESSMENT")
    if not connections:
        print("No TCP connections observed.")
        return

    header = (
        f"{'SRC':<21} {'DST':<21} "
        f"{'PKTS':>6} {'BYTES':>8} "
        f"{'RISK':>6} {'LEVEL':>8}"
    )
    print(header)
    print("-" * len(header))

    for conn in connections:
        row = (
            f"{(str(conn['src_ip']) + ':' + str(conn['src_port'])):<21} "
            f"{(str(conn['dst_ip']) + ':' + str(conn['dst_port'])):<21} "
            f"{int(conn['packet_count']):>6} "
            f"{int(conn['byte_count']):>8} "
            f"{int(conn['risk_score']):>6} "
            f"{str(conn['risk_level']):>8}"
        )
        print(row)



def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    configure_logging(verbose=args.verbose)
    logger = logging.getLogger(__name__)

    pcap_path = Path(args.pcap)
    if not pcap_path.is_file():
        logger.error("PCAP file not found: %s", pcap_path)
        raise SystemExit(1)

    json_out = Path(args.json_out) if args.json_out else None

    report = analyze_pcap(pcap_path, json_out=json_out)
    print_human_report(report)


if __name__ == "__main__":
    main()

