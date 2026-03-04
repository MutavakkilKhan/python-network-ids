from __future__ import annotations

from typing import Optional

from scapy.all import Packet  # type: ignore[import]


class SNIExtractor:
    """
    Extract TLS Server Name Indication (SNI) from TLS Client Hello messages.

    This implementation performs a lightweight parse of the TLS ClientHello
    record directly from the TCP payload, so it does not depend on Scapy's
    optional TLS layers being installed.
    """

    def extract_sni(self, packet: Packet) -> Optional[str]:
        raw_layer = packet.getlayer("Raw")
        if raw_layer is None or not getattr(raw_layer, "load", None):
            return None

        try:
            payload: bytes = raw_layer.load  # type: ignore[assignment]
        except Exception:
            return None

        try:
            return self._parse_sni_from_client_hello(payload)
        except Exception:
            # Parsing is intentionally best-effort; failures should not break analysis.
            return None

    def _parse_sni_from_client_hello(self, data: bytes) -> Optional[str]:
        """
        Minimal TLS ClientHello parser to extract SNI.

        This follows RFC 5246 / RFC 6066 structures and assumes a single
        TLS record containing a ClientHello handshake.
        """
        if len(data) < 5:
            return None

        content_type = data[0]
        if content_type != 0x16:  # 22 = Handshake
            return None

        # Record header: 1 byte type, 2 bytes version, 2 bytes length
        # Handshake message starts at offset 5
        handshake_start = 5
        if len(data) < handshake_start + 4:
            return None

        handshake_type = data[handshake_start]
        if handshake_type != 0x01:  # 1 = ClientHello
            return None

        # Skip handshake header (1 type + 3 length)
        p = handshake_start + 4

        # ClientHello:
        # 2 bytes version
        if len(data) < p + 2:
            return None
        p += 2

        # 32 bytes random
        if len(data) < p + 32:
            return None
        p += 32

        # Session ID
        if len(data) < p + 1:
            return None
        session_id_len = data[p]
        p += 1 + session_id_len
        if len(data) < p:
            return None

        # Cipher Suites
        if len(data) < p + 2:
            return None
        cipher_suites_len = int.from_bytes(data[p : p + 2], "big")
        p += 2 + cipher_suites_len
        if len(data) < p:
            return None

        # Compression Methods
        if len(data) < p + 1:
            return None
        comp_methods_len = data[p]
        p += 1 + comp_methods_len
        if len(data) < p:
            return None

        # Extensions length
        if len(data) < p + 2:
            return None
        extensions_len = int.from_bytes(data[p : p + 2], "big")
        p += 2
        end_extensions = p + extensions_len
        if len(data) < end_extensions:
            return None

        # Iterate over extensions
        while p + 4 <= end_extensions:
            ext_type = int.from_bytes(data[p : p + 2], "big")
            ext_len = int.from_bytes(data[p + 2 : p + 4], "big")
            p += 4
            if p + ext_len > end_extensions:
                break

            if ext_type == 0x0000:  # server_name
                # Server Name extension structure:
                # 2 bytes list length, then entries:
                # 1 byte name_type, 2 bytes name length, then name bytes
                ext_data = data[p : p + ext_len]
                if len(ext_data) < 2:
                    return None
                list_len = int.from_bytes(ext_data[0:2], "big")
                q = 2
                if len(ext_data) < 2 + list_len:
                    return None
                # Parse first entry only
                if q + 3 > len(ext_data):
                    return None
                name_type = ext_data[q]
                if name_type != 0x00:  # host_name
                    return None
                name_len = int.from_bytes(ext_data[q + 1 : q + 3], "big")
                q += 3
                if q + name_len > len(ext_data):
                    return None
                server_name_bytes = ext_data[q : q + name_len]
                try:
                    return server_name_bytes.decode("utf-8")
                except Exception:
                    return None

            p += ext_len

        return None

