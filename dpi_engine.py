from __future__ import annotations

from typing import Iterable, List

from scapy.all import Packet  # type: ignore[import]


class DPIEngine:
    """
    Simple Deep Packet Inspection engine that searches for
    suspicious keywords in TCP payloads.
    """

    def __init__(self, suspicious_keywords: Iterable[str]) -> None:
        # Normalize all keywords to lowercase for case-insensitive matching
        self._keywords = [kw.lower() for kw in suspicious_keywords]

    def inspect_packet(self, packet: Packet) -> List[str]:
        """
        Inspect a packet and return matching suspicious keywords, if any.
        """
        raw_layer = packet.getlayer("Raw")
        if raw_layer is None or not getattr(raw_layer, "load", None):
            return []

        try:
            payload_bytes: bytes = raw_layer.load  # type: ignore[assignment]
        except Exception:
            return []

        try:
            payload_str = payload_bytes.decode(errors="ignore").lower()
        except Exception:
            return []

        matches = {kw for kw in self._keywords if kw and kw in payload_str}
        return sorted(matches)

