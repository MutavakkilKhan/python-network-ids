"""
Global configuration for the packet analyzer and lightweight IDS.

You can tune these lists and thresholds to match your environment
or to demonstrate different detection behaviors during interviews.
"""

from __future__ import annotations

from typing import Dict, List

# Domains that should immediately raise suspicion when observed in TLS SNI.
BLACKLISTED_DOMAINS: List[str] = [
    "malicious.example",
    "evilcorp.test",
    "cnc.botnet.local",
]

# Case-insensitive keywords to search for in application payloads.
SUSPICIOUS_KEYWORDS: List[str] = [
    "password",
    "login",
    "credential",
    "select * from",
    "union select",
    "drop table",
    "cmd.exe",
    "powershell",
    "exec(",
]

# Number of distinct destination ports contacted by a single source IP
# before it is considered a port scan.
PORT_SCAN_THRESHOLD: int = 20

# Risk score thresholds. Interpretation:
# - score < MEDIUM  -> LOW
# - MEDIUM <= score < HIGH -> MEDIUM
# - score >= HIGH -> HIGH
RISK_THRESHOLDS: Dict[str, int] = {
    "LOW": 0,
    "MEDIUM": 5,
    "HIGH": 10,
}

