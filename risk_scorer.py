from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple

from connection_tracker import ConnectionKey, ConnectionStats
from rule_manager import RuleManager


@dataclass
class ConnectionRisk:
    score: int = 0
    suspicious_keywords: Set[str] = field(default_factory=set)
    blacklisted_domains: Set[str] = field(default_factory=set)
    port_scan_flag: bool = False


class RiskScorer:
    """
    Dynamic risk scoring for each TCP connection.

    Default scoring model:
    - +2 per suspicious payload keyword match
    - +5 per blacklisted domain access
    - +3 when source IP is involved in port scanning
    """

    def __init__(self, rule_manager: RuleManager) -> None:
        self._rm = rule_manager
        self._risks: Dict[ConnectionKey, ConnectionRisk] = {}

        thresholds = self._rm.risk_thresholds
        self._medium_threshold = int(thresholds.get("MEDIUM", 5))
        self._high_threshold = int(thresholds.get("HIGH", 10))

    @property
    def risks(self) -> Dict[ConnectionKey, ConnectionRisk]:
        return self._risks

    def _get(self, key: ConnectionKey) -> ConnectionRisk:
        if key not in self._risks:
            self._risks[key] = ConnectionRisk()
        return self._risks[key]

    def add_suspicious_payload(self, key: ConnectionKey, matched_keywords: List[str]) -> None:
        if not matched_keywords:
            return
        risk = self._get(key)
        for kw in matched_keywords:
            if kw not in risk.suspicious_keywords:
                risk.suspicious_keywords.add(kw)
                risk.score += 2

    def add_blacklisted_domain(self, key: ConnectionKey, domain: str) -> None:
        risk = self._get(key)
        if domain not in risk.blacklisted_domains:
            risk.blacklisted_domains.add(domain)
            risk.score += 5

    def add_port_scan_flag(self, key: ConnectionKey) -> None:
        risk = self._get(key)
        if not risk.port_scan_flag:
            risk.port_scan_flag = True
            risk.score += 3

    def risk_level(self, score: int) -> str:
        if score >= self._high_threshold:
            return "HIGH"
        if score >= self._medium_threshold:
            return "MEDIUM"
        return "LOW"

    def summarize_connection(
        self,
        key: ConnectionKey,
        stats: ConnectionStats,
    ) -> Dict[str, object]:
        risk = self._risks.get(key, ConnectionRisk())
        level = self.risk_level(risk.score)
        return {
            "src_ip": stats.src_ip,
            "src_port": stats.src_port,
            "dst_ip": stats.dst_ip,
            "dst_port": stats.dst_port,
            "packet_count": stats.packet_count,
            "byte_count": stats.byte_count,
            "risk_score": risk.score,
            "risk_level": level,
            "suspicious_keywords": sorted(risk.suspicious_keywords),
            "blacklisted_domains": sorted(risk.blacklisted_domains),
            "port_scan_flag": risk.port_scan_flag,
        }

