from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Recommendation:
    code: str
    title: str
    risk: str
    fix: str
    nginx: Optional[str] = None
    apache: Optional[str] = None
    iis: Optional[str] = None


@dataclass
class Finding:
    severity: str
    code: str
    category: str
    title: str
    detail: str
    recommendation: Recommendation
    evidence: Dict[str, Any] = field(default_factory=dict)
    grade_cap: Optional[str] = None
    score_penalty: int = 0


@dataclass
class Report:
    host: str
    port: int = 443
    grade: str = "D"
    score: int = 0
    summary: List[str] = field(default_factory=list)
    certificate: Dict[str, Any] = field(default_factory=dict)
    chain: Dict[str, Any] = field(default_factory=dict)
    protocols: Dict[str, Any] = field(default_factory=dict)
    cipher_suites: Dict[str, Any] = field(default_factory=dict)
    vulnerabilities: Dict[str, Any] = field(default_factory=dict)
    hsts: Dict[str, Any] = field(default_factory=dict)
    http_redirect: Dict[str, Any] = field(default_factory=dict)
    ocsp: Dict[str, Any] = field(default_factory=dict)
    russian_tls: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[Recommendation] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
