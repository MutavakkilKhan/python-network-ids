from __future__ import annotations

from pathlib import Path
from typing import List

from scapy.all import Packet, rdpcap  # type: ignore[import]


def read_pcap(file_path: str | Path) -> List[Packet]:
    """
    Read packets from a PCAP file using Scapy.

    Parameters
    ----------
    file_path:
        Path to the PCAP file.

    Returns
    -------
    List[Packet]
        List of Scapy packets.
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"PCAP file not found: {path}")

    return list(rdpcap(str(path)))

