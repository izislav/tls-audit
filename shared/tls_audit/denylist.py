import ipaddress
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple

from .validation import normalize_host


@dataclass(frozen=True)
class DenyDecision:
    allowed: bool
    reason: str = ""
    rule: str = ""


@dataclass(frozen=True)
class TargetRule:
    raw: str
    host: str
    port: Optional[int] = None
    suffix: bool = False


class Denylist:
    def __init__(
        self,
        client_ip_rules: Iterable[str] = (),
        target_rules: Iterable[str] = (),
    ) -> None:
        self.client_exact, self.client_networks = parse_client_rules(client_ip_rules)
        self.target_rules = parse_target_rules(target_rules)

    @classmethod
    def from_text(cls, client_ips: str = "", targets: str = "") -> "Denylist":
        return cls(split_rules(client_ips), split_rules(targets))

    def check_client_ip(self, client_ip: str) -> DenyDecision:
        value = (client_ip or "").strip()
        if not value:
            return DenyDecision(True)
        if value in self.client_exact:
            return DenyDecision(False, "client_ip_blocked", value)
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return DenyDecision(True)
        for network in self.client_networks:
            if ip in network:
                return DenyDecision(False, "client_ip_blocked", str(network))
        return DenyDecision(True)

    def check_target(self, host: str, port: int) -> DenyDecision:
        normalized = safe_normalize_host(host)
        for rule in self.target_rules:
            if rule.port is not None and rule.port != port:
                continue
            if rule.suffix:
                if normalized == rule.host or normalized.endswith("." + rule.host):
                    return DenyDecision(False, "target_blocked", rule.raw)
                continue
            if normalized == rule.host:
                return DenyDecision(False, "target_blocked", rule.raw)
        return DenyDecision(True)


def split_rules(value: str) -> List[str]:
    rules = []
    for item in value.replace("\n", ",").split(","):
        rule = item.strip()
        if rule:
            rules.append(rule)
    return rules


def parse_client_rules(rules: Iterable[str]) -> Tuple[set[str], List[ipaddress._BaseNetwork]]:
    exact = set()
    networks = []
    for rule in rules:
        value = rule.strip()
        if not value:
            continue
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
            continue
        except ValueError:
            exact.add(value)
    return exact, networks


def parse_target_rules(rules: Iterable[str]) -> List[TargetRule]:
    parsed = []
    for rule in rules:
        value = rule.strip().lower()
        if not value:
            continue
        host_part, port = split_target_rule(value)
        suffix = False
        if host_part.startswith("*."):
            suffix = True
            host_part = host_part[2:]
        elif host_part.startswith("."):
            suffix = True
            host_part = host_part[1:]
        if not host_part:
            continue
        parsed.append(
            TargetRule(
                raw=rule.strip(),
                host=safe_normalize_host(host_part),
                port=port,
                suffix=suffix,
            )
        )
    return parsed


def split_target_rule(rule: str) -> Tuple[str, Optional[int]]:
    if rule.count(":") != 1:
        return rule, None
    host, raw_port = rule.rsplit(":", 1)
    try:
        port = int(raw_port)
    except ValueError:
        return rule, None
    if port < 1 or port > 65535:
        return host, None
    return host, port


def safe_normalize_host(host: str) -> str:
    try:
        return normalize_host(host)
    except UnicodeError:
        return host.rstrip(".").lower()
