from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Set

from scapy.all import Packet  # type: ignore[import]


@dataclass
class PortScanAlert:
    source_ip: str
    unique_ports: int


class AnomalyDetector:
    """
    Detect simple behavioral anomalies such as port scanning.

    For each source IP, we track the set of unique destination ports.
    If the count exceeds a configurable threshold, we emit an alert.
    """

    def __init__(self, port_scan_threshold: int) -> None:
        self._threshold = port_scan_threshold
        self._ports_by_src: Dict[str, Set[int]] = {}
        self._alerted_sources: Set[str] = set()
        self._alerts: List[PortScanAlert] = []

    @property
    def alerts(self) -> List[PortScanAlert]:
        return self._alerts

    @property
    def suspicious_sources(self) -> Set[str]:
        return set(self._alerted_sources)

    def observe_packet(self, packet: Packet) -> None:
        ip_layer = packet.getlayer("IP")
        tcp_layer = packet.getlayer("TCP")
        if ip_layer is None or tcp_layer is None:
            return

        src_ip = ip_layer.src
        dst_port = int(tcp_layer.dport)

        ports = self._ports_by_src.setdefault(src_ip, set())
        ports.add(dst_port)

        if src_ip not in self._alerted_sources and len(ports) >= self._threshold:
            self._alerted_sources.add(src_ip)
            self._alerts.append(PortScanAlert(source_ip=src_ip, unique_ports=len(ports)))

