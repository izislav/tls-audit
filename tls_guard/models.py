from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class CertificateInfo:
    subject: Optional[str] = None
    issuer: Optional[str] = None
    common_names: List[str] = field(default_factory=list)
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    expires_in_days: Optional[int] = None
    expired: bool = False
    serial_number: Optional[str] = None
    fingerprint_sha256: Optional[str] = None
    subject_alt_names: List[str] = field(default_factory=list)
    signature_algorithm: Optional[str] = None
    public_key_algorithm: Optional[str] = None
    public_key_bits: Optional[int] = None
    chain_length: int = 0
    trusted: bool = False
    validation_error: Optional[str] = None


@dataclass
class ProtocolCheck:
    version: str
    supported: bool
    cipher: Optional[str] = None
    cipher_bits: Optional[int] = None
    negotiated_protocol: Optional[str] = None
    error: Optional[str] = None


@dataclass
class CipherProbe:
    name: str
    protocol: str
    accepted: bool
    issue: str
    error: Optional[str] = None


@dataclass
class HeaderInfo:
    hsts: Optional[str] = None
    hsts_max_age: Optional[int] = None
    hsts_include_subdomains: bool = False
    hsts_preload: bool = False
    server: Optional[str] = None
    status: Optional[int] = None
    content_security_policy: Optional[str] = None
    x_content_type_options: Optional[str] = None
    x_frame_options: Optional[str] = None
    referrer_policy: Optional[str] = None
    error: Optional[str] = None


@dataclass
class Finding:
    severity: str
    code: str
    category: str
    title: str
    detail: str
    recommendation: str


@dataclass
class ScanResult:
    target: str
    host: str
    port: int
    addresses: List[str]
    certificate: CertificateInfo
    protocols: List[ProtocolCheck]
    cipher_probes: List[CipherProbe]
    headers: HeaderInfo
    findings: List[Finding]
    grade: str
    score: int
    scanned_at: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
