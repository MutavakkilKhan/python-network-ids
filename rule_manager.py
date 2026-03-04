from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Dict


@dataclass
class RuleConfig:
    blacklisted_domains: List[str]
    suspicious_keywords: List[str]
    port_scan_threshold: int
    risk_thresholds: Dict[str, int]


class RuleManager:
    """
    Thin wrapper around static configuration values, so that
    policy and configuration are centralized and can evolve.
    """

    def __init__(self, config: RuleConfig) -> None:
        self._config = config
        self._domain_set = {d.lower() for d in config.blacklisted_domains}

    @classmethod
    def from_module(cls, config_module: object) -> "RuleManager":
        blacklist = list(getattr(config_module, "BLACKLISTED_DOMAINS", []))
        keywords = list(getattr(config_module, "SUSPICIOUS_KEYWORDS", []))
        port_scan_threshold = int(getattr(config_module, "PORT_SCAN_THRESHOLD", 20))
        risk_thresholds = dict(getattr(config_module, "RISK_THRESHOLDS", {}))
        cfg = RuleConfig(
            blacklisted_domains=blacklist,
            suspicious_keywords=keywords,
            port_scan_threshold=port_scan_threshold,
            risk_thresholds=risk_thresholds,
        )
        return cls(cfg)

    @property
    def suspicious_keywords(self) -> Iterable[str]:
        return self._config.suspicious_keywords

    @property
    def blacklisted_domains(self) -> Iterable[str]:
        return self._config.blacklisted_domains

    @property
    def port_scan_threshold(self) -> int:
        return self._config.port_scan_threshold

    @property
    def risk_thresholds(self) -> Dict[str, int]:
        return self._config.risk_thresholds

    def is_domain_blacklisted(self, domain: str) -> bool:
        return domain.lower() in self._domain_set

