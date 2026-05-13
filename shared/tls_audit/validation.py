import ipaddress
import re
import socket
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Set, Tuple
from urllib.parse import urlsplit


CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
METADATA_IPS = {
    ipaddress.ip_address("169.254.169.254"),
}
BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "metadata",
    "metadata.google.internal",
}
BLOCKED_PORTS = {
    1,
    7,
    9,
    13,
    17,
    19,
    20,
    21,
    22,
    23,
    25,
    37,
    53,
    69,
    79,
    110,
    111,
    119,
    123,
    135,
    137,
    138,
    139,
    143,
    161,
    162,
    389,
    427,
    445,
    465,
    500,
    514,
    515,
    587,
    631,
    636,
    873,
    993,
    995,
    1080,
    1433,
    1521,
    2049,
    2375,
    2376,
    2483,
    2484,
    3306,
    3389,
    4369,
    5060,
    5061,
    5432,
    5672,
    5900,
    5984,
    5985,
    5986,
    6000,
    6379,
    6443,
    6667,
    7001,
    7002,
    7199,
    9200,
    9300,
    11211,
    15672,
    27017,
    27018,
    27019,
}


@dataclass
class Target:
    host: str
    port: int = 443
    addresses: List[str] = field(default_factory=list)


def validate_target(raw_host: str, port: int = 443, resolve: bool = True) -> Target:
    host, parsed_port = parse_host(raw_host, port)
    target = Target(host=host, port=parsed_port)
    if resolve:
        target.addresses = resolve_public_addresses(host, parsed_port)
    return target


def validate_worker_target(
    host: str,
    port: int,
    expected_addresses: Optional[Iterable[str]] = None,
) -> Target:
    target = validate_target(host, port, resolve=True)
    expected = normalize_addresses(expected_addresses or [])
    current = normalize_addresses(target.addresses)
    if expected and current.isdisjoint(expected):
        raise ValueError(
            "DNS-ответ изменился после постановки проверки в очередь. "
            "Повторите скан, чтобы подтвердить актуальный публичный IP."
        )
    return target


def parse_host(raw_host: str, default_port: int = 443) -> Tuple[str, int]:
    value = raw_host.strip()
    if not value or CONTROL_CHARS.search(value):
        raise ValueError("Укажите домен без управляющих символов.")

    if "://" in value:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("Разрешены только http/https URL.")
    else:
        parsed = urlsplit(f"//{value}", scheme="https")

    if parsed.username or parsed.password or parsed.path not in {"", "/"}:
        raise ValueError("Укажите только домен и необязательный порт, без пути и логина.")
    if parsed.query or parsed.fragment:
        raise ValueError("Query string и fragment не поддерживаются.")
    if not parsed.hostname:
        raise ValueError("Домен обязателен.")

    host = normalize_host(parsed.hostname)
    if host in BLOCKED_HOSTNAMES:
        raise ValueError("Этот служебный hostname запрещён для сканирования.")
    if "*" in host:
        raise ValueError("Wildcard-домены нельзя сканировать как цель.")

    try:
        parsed_port = parsed.port or default_port
    except ValueError as exc:
        raise ValueError("Порт должен быть числом от 1 до 65535.") from exc
    if parsed_port < 1 or parsed_port > 65535:
        raise ValueError("Порт должен быть от 1 до 65535.")
    if parsed_port in BLOCKED_PORTS:
        raise ValueError(f"Порт {parsed_port} запрещён для публичного сканирования.")
    return host, parsed_port


def normalize_host(hostname: str) -> str:
    host = hostname.rstrip(".").lower()
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host.encode("idna").decode("ascii").lower()
    return str(ip)


def resolve_public_addresses(host: str, port: int) -> List[str]:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"DNS не разрешился: {exc}") from exc

    addresses = []
    for info in infos:
        address = info[4][0]
        if address in addresses:
            continue
        if not is_public_address(address):
            raise ValueError(f"Адрес {address} запрещён для сканирования.")
        addresses.append(address)

    if not addresses:
        raise ValueError("DNS не вернул адресов для сканирования.")
    return addresses


def is_public_address(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    if ip in METADATA_IPS:
        return False
    return ip.is_global


def normalize_addresses(addresses: Iterable[str]) -> Set[str]:
    normalized = set()
    for address in addresses:
        try:
            normalized.add(str(ipaddress.ip_address(str(address))))
        except ValueError:
            continue
    return normalized
