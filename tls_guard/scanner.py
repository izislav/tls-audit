import argparse
import datetime as dt
import http.client
import ipaddress
import json
import math
import re
import socket
import ssl
import subprocess
import time
from typing import Callable, Dict, Iterable, List, Optional, Tuple, TypeVar
from urllib.parse import urlsplit

from .models import (
    CertificateInfo,
    CipherProbe,
    Finding,
    HeaderInfo,
    ProtocolCheck,
    ScanResult,
)


DEFAULT_TIMEOUT = 6.0
DEFAULT_SCAN_MAX_SECONDS = 45.0
PUBLIC_D_FLOOR = 40
RETRY_ATTEMPTS = 3
RETRY_DELAY_SECONDS = 0.25
CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
PEM_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL
)


TLS_VERSION_MAP: List[Tuple[str, ssl.TLSVersion]] = [
    ("TLS 1.0", ssl.TLSVersion.TLSv1),
    ("TLS 1.1", ssl.TLSVersion.TLSv1_1),
    ("TLS 1.2", ssl.TLSVersion.TLSv1_2),
    ("TLS 1.3", ssl.TLSVersion.TLSv1_3),
]

WEAK_CIPHER_PROBES: List[Tuple[str, str]] = [
    ("NULL-SHA", "NULL cipher, no encryption"),
    ("EXP-RC4-MD5", "export-grade cipher"),
    ("RC4-SHA", "RC4 stream cipher"),
    ("DES-CBC3-SHA", "3DES / SWEET32 risk"),
    ("AES128-SHA", "CBC cipher without AEAD"),
    ("AES256-SHA", "CBC cipher without AEAD"),
    ("ECDHE-RSA-AES128-SHA", "CBC cipher without AEAD"),
    ("ECDHE-RSA-AES256-SHA", "CBC cipher without AEAD"),
]

T = TypeVar("T")
ProgressCallback = Callable[[int, str, str], None]


def retry_network(operation: Callable[[], T], attempts: int = RETRY_ATTEMPTS) -> T:
    last_exc = None
    for attempt in range(attempts):
        try:
            return operation()
        except (socket.gaierror, socket.timeout, TimeoutError, OSError) as exc:
            last_exc = exc
            if attempt == attempts - 1:
                break
            time.sleep(RETRY_DELAY_SECONDS * (attempt + 1))
    if last_exc:
        raise last_exc
    raise RuntimeError("Network operation did not run.")


def open_connection(host: str, port: int, timeout: float) -> socket.socket:
    return retry_network(lambda: socket.create_connection((host, port), timeout=timeout))


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(
        self,
        host: str,
        address: str,
        port: int,
        timeout: float,
        context: ssl.SSLContext,
    ) -> None:
        super().__init__(host=host, port=port, timeout=timeout, context=context)
        self.address = address

    def connect(self) -> None:
        raw_socket = socket.create_connection((self.address, self.port), timeout=self.timeout)
        self.sock = self._context.wrap_socket(raw_socket, server_hostname=self.host)


def connect_target(address: str, port: int) -> str:
    if ":" in address:
        return f"[{address}]:{port}"
    return f"{address}:{port}"


def parse_target(raw_target: str) -> Tuple[str, int]:
    raw_target = raw_target.strip()
    if not raw_target or CONTROL_CHARS.search(raw_target):
        raise ValueError("Target must be a hostname with optional port.")

    if "://" in raw_target:
        parsed = urlsplit(raw_target)
        if parsed.scheme not in {"https", "http"}:
            raise ValueError("Only http/https URLs are accepted.")
    else:
        parsed = urlsplit(f"//{raw_target}", scheme="https")

    if parsed.username or parsed.password or parsed.path not in {"", "/"}:
        raise ValueError("Use only a hostname and optional port, not a full path.")
    if parsed.query or parsed.fragment:
        raise ValueError("Query strings and fragments are not accepted.")

    host = parsed.hostname
    if not host:
        raise ValueError("Hostname is required.")

    host = host.rstrip(".").encode("idna").decode("ascii").lower()
    if "*" in host:
        raise ValueError("Wildcards are not accepted.")

    port = parsed.port or 443
    if port < 1 or port > 65535:
        raise ValueError("Port must be between 1 and 65535.")

    return host, port


def resolve_addresses(host: str, port: int, allow_private: bool = False) -> List[str]:
    try:
        infos = retry_network(
            lambda: socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        )
    except socket.gaierror as exc:
        raise ValueError(f"DNS resolution failed: {exc}") from exc

    addresses: List[str] = []
    for info in infos:
        address = info[4][0]
        if address not in addresses:
            addresses.append(address)

    if not addresses:
        raise ValueError("DNS returned no usable addresses.")

    if allow_private:
        return addresses

    blocked = []
    allowed = []
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if ip.is_global:
            allowed.append(address)
        else:
            blocked.append(address)

    if blocked and not allowed:
        raise ValueError(
            "Target resolves only to non-public addresses; refusing to scan it."
        )
    return allowed


def scan_host(
    raw_target: str,
    timeout: float = DEFAULT_TIMEOUT,
    allow_private: bool = False,
    progress_callback: Optional[ProgressCallback] = None,
    max_seconds: float = DEFAULT_SCAN_MAX_SECONDS,
    expected_addresses: Optional[Iterable[str]] = None,
) -> ScanResult:
    started_at = time.monotonic()
    deadline = started_at + max_seconds

    def progress(percent: int, stage: str, detail: str) -> None:
        if progress_callback:
            progress_callback(percent, stage, detail)

    def ensure_deadline() -> None:
        if time.monotonic() > deadline:
            raise TimeoutError(
                f"Scan exceeded {int(max_seconds)} second limit before completion."
            )

    progress(2, "validate", "Проверяем формат цели")
    host, port = parse_target(raw_target)
    ensure_deadline()
    progress(8, "dns", "Разрешаем DNS и проверяем, что адрес публичный")
    addresses = resolve_addresses(host, port, allow_private=allow_private)
    expected = {str(ipaddress.ip_address(value)) for value in (expected_addresses or [])}
    if expected and expected.isdisjoint(addresses):
        raise ValueError("DNS changed after the scan was queued; refusing to continue.")
    connection_host = next((address for address in addresses if not expected or address in expected), addresses[0])
    ensure_deadline()
    progress(18, "certificate", "Получаем и анализируем сертификат")
    certificate = fetch_certificate_info(host, port, timeout, connection_host=connection_host)
    ensure_deadline()

    protocols = []
    for index, (name, version) in enumerate(TLS_VERSION_MAP):
        progress(
            30 + index * 8,
            "tls_versions",
            f"Проверяем поддержку {name}",
        )
        protocols.append(check_protocol(host, port, name, version, timeout, connection_host=connection_host))
        ensure_deadline()

    cipher_probes = []
    for index, (cipher_name, issue) in enumerate(WEAK_CIPHER_PROBES):
        progress(
            64 + index * 3,
            "cipher_suites",
            f"Проверяем слабый cipher suite: {cipher_name}",
        )
        cipher_probes.append(
            check_cipher(host, port, cipher_name, issue, timeout, connection_host=connection_host)
        )
        ensure_deadline()

    progress(90, "headers", "Получаем HTTP security headers")
    headers = fetch_headers(host, port, timeout, connection_host=connection_host)
    ensure_deadline()
    progress(96, "grading", "Считаем оценку и формируем рекомендации")
    findings, grade, score = evaluate(certificate, protocols, cipher_probes, headers)
    progress(100, "done", "Проверка завершена")

    return ScanResult(
        target=raw_target,
        host=host,
        port=port,
        addresses=addresses,
        certificate=certificate,
        protocols=protocols,
        cipher_probes=cipher_probes,
        headers=headers,
        findings=findings,
        grade=grade,
        score=score,
        scanned_at=dt.datetime.now(dt.timezone.utc).isoformat(),
    )


def fetch_certificate_info(
    host: str,
    port: int,
    timeout: float,
    connection_host: Optional[str] = None,
) -> CertificateInfo:
    cert = CertificateInfo()
    validated_peer = None
    target = connection_host or host

    try:
        context = ssl.create_default_context()
        with open_connection(target, port, timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                validated_peer = tls.getpeercert()
                cert.trusted = True
    except Exception as exc:  # noqa: BLE001 - validation errors are report data here.
        cert.trusted = False
        cert.validation_error = str(exc)

    if validated_peer:
        apply_peer_cert_dict(cert, validated_peer)
    else:
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with open_connection(target, port, timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls:
                    apply_peer_cert_dict(cert, tls.getpeercert())
        except Exception:
            pass

    chain = fetch_pem_chain(host, port, timeout, connection_host=target)
    cert.chain_length = len(chain)
    if chain:
        details = inspect_leaf_certificate(chain[0], timeout)
        apply_openssl_details(cert, details)

    return cert


def apply_peer_cert_dict(cert: CertificateInfo, peer: Dict[str, object]) -> None:
    subject = format_name(peer.get("subject"))
    issuer = format_name(peer.get("issuer"))
    if subject:
        cert.subject = subject
    if issuer:
        cert.issuer = issuer
    cert.not_before = str(peer.get("notBefore") or cert.not_before or "")
    cert.not_after = str(peer.get("notAfter") or cert.not_after or "")
    cert.serial_number = str(peer.get("serialNumber") or cert.serial_number or "")

    san = peer.get("subjectAltName") or []
    names = []
    if isinstance(san, Iterable):
        for item in san:
            if isinstance(item, tuple) and len(item) == 2 and item[0] == "DNS":
                names.append(str(item[1]))
    cert.subject_alt_names = sorted(set(names))
    cert.common_names = extract_common_names(peer.get("subject"))


def format_name(value: object) -> Optional[str]:
    if not isinstance(value, tuple):
        return None

    parts: List[str] = []
    for rdn in value:
        if not isinstance(rdn, tuple):
            continue
        for item in rdn:
            if isinstance(item, tuple) and len(item) == 2:
                parts.append(f"{item[0]}={item[1]}")
    return ", ".join(parts) if parts else None


def extract_common_names(value: object) -> List[str]:
    if not isinstance(value, tuple):
        return []

    names: List[str] = []
    for rdn in value:
        if not isinstance(rdn, tuple):
            continue
        for item in rdn:
            if isinstance(item, tuple) and len(item) == 2 and item[0] == "commonName":
                names.append(str(item[1]))
    return names


def fetch_pem_chain(
    host: str,
    port: int,
    timeout: float,
    connection_host: Optional[str] = None,
) -> List[str]:
    target = connection_host or host
    command = [
        "openssl",
        "s_client",
        "-connect",
        connect_target(target, port),
        "-servername",
        host,
        "-showcerts",
    ]
    for attempt in range(RETRY_ATTEMPTS):
        try:
            completed = subprocess.run(
                command,
                input="",
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except Exception:
            if attempt < RETRY_ATTEMPTS - 1:
                time.sleep(RETRY_DELAY_SECONDS * (attempt + 1))
                continue
            return []

        chain = PEM_RE.findall(completed.stdout + completed.stderr)
        if chain or attempt == RETRY_ATTEMPTS - 1:
            return chain
        time.sleep(RETRY_DELAY_SECONDS * (attempt + 1))
    return []


def inspect_leaf_certificate(pem: str, timeout: float) -> Dict[str, str]:
    command = [
        "openssl",
        "x509",
        "-noout",
        "-subject",
        "-issuer",
        "-dates",
        "-serial",
        "-fingerprint",
        "-sha256",
        "-text",
    ]
    try:
        completed = subprocess.run(
            command,
            input=pem,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except Exception:
        return {}

    details: Dict[str, str] = {}
    for line in completed.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("Signature Algorithm:") and "signature_algorithm" not in details:
            details["signature_algorithm"] = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("Public Key Algorithm:"):
            details["public_key_algorithm"] = stripped.split(":", 1)[1].strip()
        elif "Public-Key:" in stripped:
            match = re.search(r"\((\d+) bit\)", stripped)
            if match:
                details["public_key_bits"] = match.group(1)

        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        details[key.strip()] = value.strip()
    return details


def apply_openssl_details(cert: CertificateInfo, details: Dict[str, str]) -> None:
    if details.get("subject"):
        cert.subject = details["subject"]
    if details.get("issuer"):
        cert.issuer = details["issuer"]
    if details.get("notBefore"):
        cert.not_before = details["notBefore"]
    if details.get("notAfter"):
        cert.not_after = details["notAfter"]
    if details.get("serial"):
        cert.serial_number = details["serial"]

    fingerprint = details.get("sha256 Fingerprint")
    if fingerprint:
        cert.fingerprint_sha256 = fingerprint.replace(":", "").lower()

    if details.get("signature_algorithm"):
        cert.signature_algorithm = details["signature_algorithm"]
    if details.get("public_key_algorithm"):
        cert.public_key_algorithm = details["public_key_algorithm"]
    if details.get("public_key_bits"):
        try:
            cert.public_key_bits = int(details["public_key_bits"])
        except ValueError:
            cert.public_key_bits = None

    cert.expired, cert.expires_in_days = certificate_expiry_state(cert.not_after)


def certificate_expiry_state(not_after: Optional[str]) -> Tuple[bool, Optional[int]]:
    if not not_after:
        return False, None

    formats = [
        "%b %d %H:%M:%S %Y %Z",
        "%b  %d %H:%M:%S %Y %Z",
        "%Y%m%d%H%M%SZ",
    ]
    parsed = None
    for fmt in formats:
        try:
            parsed = dt.datetime.strptime(not_after, fmt)
            break
        except ValueError:
            continue

    if not parsed:
        return False, None

    parsed = parsed.replace(tzinfo=dt.timezone.utc)
    delta = parsed - dt.datetime.now(dt.timezone.utc)
    days = math.floor(delta.total_seconds() / 86400)
    return days < 0, days


def check_protocol(
    host: str,
    port: int,
    name: str,
    version: ssl.TLSVersion,
    timeout: float,
    connection_host: Optional[str] = None,
) -> ProtocolCheck:
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = version
        context.maximum_version = version
        try:
            context.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass

        with open_connection(connection_host or host, port, timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cipher = tls.cipher()
                cipher_name = cipher[0] if cipher else None
                cipher_bits = int(cipher[2]) if cipher and len(cipher) > 2 else None
                return ProtocolCheck(
                    version=name,
                    supported=True,
                    cipher=cipher_name,
                    cipher_bits=cipher_bits,
                    negotiated_protocol=tls.version(),
                )
    except Exception as exc:  # noqa: BLE001 - this is result data, not control flow.
        return ProtocolCheck(version=name, supported=False, error=short_error(exc))


def check_weak_ciphers(
    host: str,
    port: int,
    timeout: float,
    connection_host: Optional[str] = None,
) -> List[CipherProbe]:
    probes: List[CipherProbe] = []
    for cipher_name, issue in WEAK_CIPHER_PROBES:
        probes.append(
            check_cipher(
                host,
                port,
                cipher_name,
                issue,
                timeout,
                connection_host=connection_host,
            )
        )
    return probes


def check_cipher(
    host: str,
    port: int,
    cipher_name: str,
    issue: str,
    timeout: float,
    connection_host: Optional[str] = None,
) -> CipherProbe:
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        context.set_ciphers(f"{cipher_name}:@SECLEVEL=0")

        with open_connection(connection_host or host, port, timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                negotiated = tls.cipher()
                accepted = bool(negotiated and negotiated[0] == cipher_name)
                return CipherProbe(
                    name=cipher_name,
                    protocol=tls.version() or "TLS 1.2",
                    accepted=accepted,
                    issue=issue,
                    error=None if accepted else "Server negotiated another cipher.",
                )
    except Exception as exc:  # noqa: BLE001 - probe failures are expected report data.
        return CipherProbe(
            name=cipher_name,
            protocol="TLS 1.2",
            accepted=False,
            issue=issue,
            error=short_error(exc),
        )


def fetch_headers(
    host: str,
    port: int,
    timeout: float,
    connection_host: Optional[str] = None,
) -> HeaderInfo:
    last_error = None
    for attempt in range(RETRY_ATTEMPTS):
        result = fetch_headers_once(host, port, timeout, connection_host=connection_host)
        if not result.error:
            return result
        last_error = result.error
        if attempt < RETRY_ATTEMPTS - 1:
            time.sleep(RETRY_DELAY_SECONDS * (attempt + 1))
    return HeaderInfo(error=last_error)


def fetch_headers_once(
    host: str,
    port: int,
    timeout: float,
    connection_host: Optional[str] = None,
) -> HeaderInfo:
    context = ssl.create_default_context()
    conn = None
    try:
        conn = PinnedHTTPSConnection(
            host,
            connection_host or host,
            port,
            timeout,
            context,
        )
        conn.request(
            "HEAD",
            "/",
            headers={"User-Agent": "TLS-Guard/0.1", "Host": host},
        )
        response = conn.getresponse()
        if response.status in {405, 501}:
            conn.close()
            conn = PinnedHTTPSConnection(
                host,
                connection_host or host,
                port,
                timeout,
                context,
            )
            conn.request(
                "GET",
                "/",
                headers={"User-Agent": "TLS-Guard/0.1", "Host": host},
            )
            response = conn.getresponse()
        headers = {key.lower(): value for key, value in response.getheaders()}
        hsts = headers.get("strict-transport-security")
        hsts_max_age, include_subdomains, preload = parse_hsts(hsts)
        return HeaderInfo(
            hsts=hsts,
            hsts_max_age=hsts_max_age,
            hsts_include_subdomains=include_subdomains,
            hsts_preload=preload,
            server=headers.get("server"),
            status=response.status,
            content_security_policy=headers.get("content-security-policy"),
            x_content_type_options=headers.get("x-content-type-options"),
            x_frame_options=headers.get("x-frame-options"),
            referrer_policy=headers.get("referrer-policy"),
        )
    except Exception as exc:  # noqa: BLE001
        return HeaderInfo(error=short_error(exc))
    finally:
        try:
            conn.close()
        except Exception:
            pass


def parse_hsts(value: Optional[str]) -> Tuple[Optional[int], bool, bool]:
    if not value:
        return None, False, False

    max_age = None
    match = re.search(r"max-age\s*=\s*(\d+)", value, flags=re.IGNORECASE)
    if match:
        max_age = int(match.group(1))

    lower = value.lower()
    return max_age, "includesubdomains" in lower, "preload" in lower


def evaluate(
    certificate: CertificateInfo,
    protocols: List[ProtocolCheck],
    cipher_probes: List[CipherProbe],
    headers: HeaderInfo,
) -> Tuple[List[Finding], str, int]:
    findings: List[Finding] = []
    supported = {item.version for item in protocols if item.supported}

    if not supported:
        add_finding(
            findings,
            "critical",
            "no_tls",
            "tls",
            "TLS endpoint недоступен",
            "Сканер не смог выполнить TLS-handshake ни с одной из проверяемых версий протокола.",
            "Проверьте, что на 443 порту работает HTTPS, сервер отдаёт сертификат и поддерживает TLS 1.2 или TLS 1.3.",
        )

    if not certificate.trusted:
        add_finding(
            findings,
            "critical",
            "certificate_trust",
            "certificate",
            "Сертификат не доверенный для этого хоста",
            certificate.validation_error
            or "Проверка сертификата не прошла во время доверенного TLS-handshake.",
            "Выпустите корректный сертификат для этого домена и установите полный chain: leaf + intermediate certificates.",
        )

    if certificate.expired:
        add_finding(
            findings,
            "critical",
            "certificate_expired",
            "certificate",
            "Срок действия сертификата истёк",
            "Клиенты должны отклонять TLS-сертификат с истёкшим сроком действия.",
            "Перевыпустите сертификат и настройте автоматическое продление, например через ACME/Let's Encrypt или панель провайдера.",
        )
    elif certificate.expires_in_days is not None and certificate.expires_in_days <= 14:
        add_finding(
            findings,
            "high",
            "certificate_expires_soon",
            "certificate",
            "Сертификат скоро истечёт",
            f"До истечения сертификата осталось дней: {certificate.expires_in_days}.",
            "Продлите сертификат заранее и проверьте, что cron/systemd timer для автообновления реально выполняется.",
        )
    elif certificate.expires_in_days is not None and certificate.expires_in_days <= 30:
        add_finding(
            findings,
            "medium",
            "certificate_expires_soon",
            "certificate",
            "Сертификат истекает в течение 30 дней",
            f"До истечения сертификата осталось дней: {certificate.expires_in_days}.",
            "Запланируйте перевыпуск сертификата и проверьте уведомления о сроке действия.",
        )

    if not certificate.subject_alt_names:
        add_finding(
            findings,
            "medium",
            "san_missing",
            "certificate",
            "В сертификате нет Subject Alternative Name",
            "Современные клиенты проверяют доменные имена через SAN, а не только через Common Name.",
            "Перевыпустите сертификат с DNS-именами в расширении subjectAltName.",
        )

    if certificate.chain_length == 1:
        add_finding(
            findings,
            "medium",
            "incomplete_chain",
            "certificate",
            "Цепочка сертификатов может быть неполной",
            "Похоже, сервер отдаёт только leaf certificate.",
            "Добавьте intermediate certificate в конфигурацию сервера: для Nginx обычно нужен fullchain.pem, не cert.pem.",
        )

    signature = (certificate.signature_algorithm or "").lower()
    if "sha1" in signature or "md5" in signature:
        add_finding(
            findings,
            "high",
            "weak_signature",
            "certificate",
            "Слабый алгоритм подписи сертификата",
            f"Алгоритм подписи leaf certificate: {certificate.signature_algorithm}.",
            "Перевыпустите сертификат с современной подписью SHA-256 или сильнее.",
        )

    key_algo = (certificate.public_key_algorithm or "").lower()
    key_bits = certificate.public_key_bits or 0
    if "rsa" in key_algo and key_bits and key_bits < 2048:
        add_finding(
            findings,
            "high",
            "weak_public_key",
            "certificate",
            "RSA public key слишком мал",
            f"Размер ключа leaf certificate: {key_bits} бит.",
            "Используйте RSA 2048/3072+ или ECDSA P-256/P-384 при следующем выпуске сертификата.",
        )

    if "TLS 1.0" in supported or "TLS 1.1" in supported:
        add_finding(
            findings,
            "high",
            "legacy_tls",
            "tls",
            "Включён устаревший TLS",
            "TLS 1.0 и TLS 1.1 лучше отключить, если нет документированной legacy-зависимости.",
            "Оставьте только TLS 1.2 и TLS 1.3. Для Nginx: ssl_protocols TLSv1.2 TLSv1.3;",
        )

    if "TLS 1.2" not in supported and "TLS 1.3" not in supported:
        add_finding(
            findings,
            "high",
            "modern_tls_missing",
            "tls",
            "Современные версии TLS недоступны",
            "Для актуальных браузеров и API нужна поддержка TLS 1.2 и TLS 1.3.",
            "Обновите web-server/OpenSSL и включите TLS 1.2/TLS 1.3 в конфигурации HTTPS.",
        )

    if "TLS 1.3" not in supported:
        add_finding(
            findings,
            "medium",
            "tls13_missing",
            "tls",
            "TLS 1.3 недоступен",
            "TLS 1.3 улучшает безопасность и скорость соединения для современных клиентов.",
            "Если версия Nginx/Apache/OpenSSL позволяет, включите TLS 1.3 вместе с TLS 1.2.",
        )

    for item in protocols:
        if item.supported and cipher_name_is_weak(item.cipher or ""):
            severity, code, title = classify_cipher_finding(item.cipher or "")
            add_finding(
                findings,
                severity,
                code,
                "cipher",
                title,
                f"{item.version} согласовал {item.cipher}.",
                "Исключите RC4, 3DES, NULL, EXPORT и CBC-only наборы. Используйте AEAD cipher suites: AES-GCM или CHACHA20-POLY1305.",
            )

    negotiated_has_aead = any(
        item.supported and cipher_name_has_aead(item.cipher or "")
        for item in protocols
    )
    for probe in cipher_probes:
        if not probe.accepted:
            continue
        severity, code, title = classify_cipher_finding(
            probe.name,
            cbc_only_hint=not negotiated_has_aead,
        )
        add_finding(
            findings,
            severity,
            code,
            "cipher",
            title,
            f"{probe.name}: {probe.issue}.",
            "Сузьте список TLS 1.2 cipher suites до ECDHE + AES-GCM/CHACHA20-POLY1305 и проверьте порядок предпочтений сервера.",
        )

    if not headers.hsts:
        add_finding(
            findings,
            "medium",
            "hsts_missing",
            "headers",
            "Нет заголовка HSTS",
            "Strict-Transport-Security стоит добавлять после проверки, что весь сайт стабильно работает по HTTPS.",
            "После проверки всего сайта добавьте Strict-Transport-Security: max-age=31536000; includeSubDomains.",
        )
    elif headers.hsts_max_age is None or headers.hsts_max_age < 15552000:
        add_finding(
            findings,
            "low",
            "hsts_weak",
            "headers",
            "HSTS max-age слишком короткий",
            "После стабилизации HTTPS стоит использовать более длинный max-age.",
            "Постепенно увеличьте max-age до 31536000. includeSubDomains включайте только если все поддомены готовы к HTTPS.",
        )

    if headers.hsts and not headers.hsts_include_subdomains:
        add_finding(
            findings,
            "info",
            "hsts_no_subdomains",
            "headers",
            "HSTS не распространяется на поддомены",
            "Текущая политика защищает только точное имя хоста.",
            "Добавьте includeSubDomains только после аудита всех поддоменов, чтобы не отключить рабочие сервисы.",
        )

    if headers.hsts and not headers.hsts_preload:
        add_finding(
            findings,
            "info",
            "hsts_preload_missing",
            "headers",
            "HSTS preload не включен",
            "Отсутствие preload не является критической уязвимостью. Это отдельный режим для сайтов, которые готовы жестко закрепить HTTPS в браузерах.",
            "Добавляйте preload только после аудита всех поддоменов и проверки, что откат не понадобится.",
        )

    if not headers.content_security_policy:
        add_finding(
            findings,
            "info",
            "csp_missing",
            "headers",
            "Нет Content-Security-Policy",
            "CSP не относится напрямую к TLS-оценке, но снижает последствия XSS.",
            "Для сайта начните с отчётного режима Content-Security-Policy-Report-Only, затем включите строгую политику.",
        )

    if not headers.x_content_type_options:
        add_finding(
            findings,
            "info",
            "x_content_type_options_missing",
            "headers",
            "Нет X-Content-Type-Options",
            "Без этого заголовка браузеры могут пытаться MIME-sniff некоторые ответы.",
            "Добавьте X-Content-Type-Options: nosniff.",
        )

    score = 100
    penalties = {"critical": 100, "high": 25, "medium": 10, "low": 5, "info": 0}
    for finding in findings:
        score -= penalties.get(finding.severity, 0)
    score = public_score(max(0, min(100, score)))

    grade = grade_from_score(score, findings, supported, headers)
    return findings, grade, score


def add_finding(
    findings: List[Finding],
    severity: str,
    code: str,
    category: str,
    title: str,
    detail: str,
    recommendation: str,
) -> None:
    findings.append(
        Finding(
            severity=severity,
            code=code,
            category=category,
            title=title,
            detail=detail,
            recommendation=recommendation,
        )
    )


def hsts_is_strong(value: str) -> bool:
    max_age, include_subdomains, _preload = parse_hsts(value)
    if max_age is None:
        return False
    return max_age >= 15552000 and include_subdomains


def cipher_name_is_weak(name: str) -> bool:
    upper = name.upper()
    weak_tokens = ["NULL", "EXPORT", "EXP-", "RC4", "3DES", "DES-CBC3", "MD5"]
    if any(token in upper for token in weak_tokens):
        return True
    if not cipher_name_has_aead(upper):
        return "AES" in upper and "SHA" in upper
    return False


def cipher_name_has_aead(name: str) -> bool:
    upper = name.upper()
    return "GCM" in upper or "CHACHA20" in upper or "POLY1305" in upper


def classify_cipher_finding(
    name: str,
    cbc_only_hint: bool = False,
) -> Tuple[str, str, str]:
    upper = name.upper()
    if any(token in upper for token in ["NULL", "EXPORT", "EXP-", "ANON", "ADH"]):
        return "critical", "weak_cipher_dangerous", "Сервер принимает опасный cipher suite"
    if "RC4" in upper:
        return "high", "weak_cipher_rc4", "Сервер принимает RC4 cipher suite"
    if "3DES" in upper or "DES-CBC3" in upper:
        return "high", "weak_cipher_3des", "Сервер принимает 3DES cipher suite"
    if not cipher_name_has_aead(upper) and "AES" in upper and "SHA" in upper:
        if cbc_only_hint:
            return "high", "weak_cipher_cbc_only", "Конфигурация выглядит как CBC-only"
        return "medium", "weak_cipher_cbc_accepted", "Сервер принимает CBC cipher suite"
    return "medium", "weak_cipher_accepted", "Сервер принимает слабый cipher suite"


def grade_from_score(
    score: int,
    findings: List[Finding],
    supported: set,
    headers: HeaderInfo,
) -> str:
    codes = {finding.code for finding in findings}
    if "certificate_trust" in codes:
        return "D"
    if "no_tls" in codes or score < 40:
        return "D"
    if score < 55:
        return "D"
    if score < 70:
        return "C"
    if score < 85:
        return "B"
    if score < 95:
        return "A"
    if "TLS 1.3" in supported and headers.hsts and hsts_is_strong(headers.hsts):
        return "A+"
    return "A"


def public_score(raw_score: int) -> int:
    if raw_score <= PUBLIC_D_FLOOR:
        return PUBLIC_D_FLOOR
    return raw_score


def short_error(exc: Exception) -> str:
    text = str(exc).strip()
    if not text:
        text = exc.__class__.__name__
    return text[:240]


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Scan a public HTTPS endpoint.")
    parser.add_argument("target", help="Hostname, host:port, or https://host[:port]")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument(
        "--allow-private",
        action="store_true",
        help="Allow private/non-global IPs for local lab testing only.",
    )
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON.")
    return parser


def main() -> None:
    args = build_arg_parser().parse_args()
    result = scan_host(args.target, timeout=args.timeout, allow_private=args.allow_private)
    print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2 if args.pretty else None))


if __name__ == "__main__":
    main()
