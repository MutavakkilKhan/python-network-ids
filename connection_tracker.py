from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Tuple

from scapy.all import Packet  # type: ignore[import]

ConnectionKey = Tuple[str, int, str, int]


@dataclass
class ConnectionStats:
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    packet_count: int = 0
    byte_count: int = 0
    first_seen_index: int | None = None
    last_seen_index: int | None = None


class ConnectionTracker:
    """
    Track TCP connections based on the 4‑tuple:
    (src_ip, src_port, dst_ip, dst_port)
    """

    def __init__(self) -> None:
        self._connections: Dict[ConnectionKey, ConnectionStats] = {}

    @property
    def connections(self) -> Dict[ConnectionKey, ConnectionStats]:
        return self._connections

    def _make_key(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> ConnectionKey:
        return src_ip, src_port, dst_ip, dst_port

    def add_packet(self, packet: Packet, index: int) -> ConnectionKey | None:
        """
        Add a TCP packet to the tracker.

        Returns the connection key for tracked packets,
        or None if the packet is not IPv4/TCP.
        """
        ip_layer = packet.getlayer("IP")
        tcp_layer = packet.getlayer("TCP")
        if ip_layer is None or tcp_layer is None:
            return None

        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        src_port = int(tcp_layer.sport)
        dst_port = int(tcp_layer.dport)
        key = self._make_key(src_ip, src_port, dst_ip, dst_port)

        stats = self._connections.get(
            key,
            ConnectionStats(
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                first_seen_index=index,
            ),
        )

        stats.packet_count += 1
        stats.byte_count += int(len(packet))
        stats.last_seen_index = index
        self._connections[key] = stats

        return key

