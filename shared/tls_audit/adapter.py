from typing import Any, Callable, Dict, List, Optional

from tls_guard.scanner import scan_host

from .recommendations import (
    CERTIFICATE_MODERN,
    CERTIFICATE_RENEWAL,
    CSP_HEADER,
    ENABLE_HSTS,
    FULLCHAIN_CERT,
    HSTS_PRELOAD_OPTIONAL,
    SECURE_CIPHERS,
    TLS12_13_ONLY,
    TLS_ENDPOINT,
    X_CONTENT_TYPE_OPTIONS,
)
from .report import Finding, Report
from .russian_trust import analyze_russian_tls
from .scoring import score_report
from .testssl import merge_testssl_result, run_testssl_scan


def run_basic_scan(
    host: str,
    port: int = 443,
    progress_callback: Optional[Callable[[int, str, str], None]] = None,
) -> Report:
    target = host if port == 443 else f"{host}:{port}"
    basic = scan_host(target, progress_callback=progress_callback)
    return normalize_basic_result(basic.to_dict())


def run_full_scan(
    host: str,
    port: int = 443,
    progress_callback: Optional[Callable[[int, str, str], None]] = None,
) -> Report:
    def basic_progress(percent: int, stage: str, detail: str) -> None:
        if progress_callback:
            progress_callback(min(85, int(percent * 0.85)), stage, detail)

    report = run_basic_scan(host, port, progress_callback=basic_progress)
    testssl_result = run_testssl_scan(host, port, progress_callback=progress_callback)
    if progress_callback:
        progress_callback(97, "scoring", "Объединяем результаты и считаем оценку")
    return merge_testssl_result(report, testssl_result)


def normalize_basic_result(raw: Dict[str, Any]) -> Report:
    report = Report(host=raw["host"], port=raw["port"], raw={"basic_scanner": raw})
    report.certificate = raw.get("certificate") or {}
    report.protocols = {"items": raw.get("protocols") or []}
    report.cipher_suites = {"weak_probes": raw.get("cipher_probes") or []}
    report.hsts = raw.get("headers") or {}
    report.findings = convert_findings(raw.get("findings") or [])
    report.russian_tls = analyze_russian_tls(report)
    return score_report(report)


def convert_findings(items: List[Dict[str, Any]]) -> List[Finding]:
    findings = []
    for item in items:
        code = item.get("code") or "unknown"
        recommendation = recommendation_for(code)
        findings.append(
            Finding(
                severity=item.get("severity") or "info",
                code=code,
                category=item.get("category") or "general",
                title=item.get("title") or code,
                detail=item.get("detail") or "",
                recommendation=recommendation,
                evidence={"source": "basic_scanner"},
                grade_cap=grade_cap_for(code),
            )
        )
    return findings


def recommendation_for(code: str):
    if code in {"no_tls"}:
        return TLS_ENDPOINT
    if code in {"certificate_expired", "certificate_expires_soon"}:
        return CERTIFICATE_RENEWAL
    if code in {"san_missing", "weak_signature", "weak_public_key", "certificate_trust"}:
        return CERTIFICATE_MODERN
    if code in {"legacy_tls", "tls13_missing", "modern_tls_missing"}:
        return TLS12_13_ONLY
    if code in {"hsts_missing", "hsts_weak", "hsts_no_subdomains"}:
        return ENABLE_HSTS
    if code in {"hsts_preload_missing"}:
        return HSTS_PRELOAD_OPTIONAL
    if code in {"csp_missing"}:
        return CSP_HEADER
    if code in {"x_content_type_options_missing"}:
        return X_CONTENT_TYPE_OPTIONS
    if code in {"incomplete_chain"}:
        return FULLCHAIN_CERT
    if code.startswith("weak_cipher_") or code == "weak_negotiated_cipher":
        return SECURE_CIPHERS
    return TLS_ENDPOINT


def grade_cap_for(code: str):
    caps = {
        "certificate_trust": "D",
        "certificate_expired": "D",
        "no_tls": "D",
        "legacy_tls": "B",
        "weak_cipher_dangerous": "D",
        "weak_cipher_rc4": "C",
        "weak_cipher_3des": "C",
        "weak_cipher_cbc_only": "C",
        "weak_cipher_cbc_accepted": "B",
        "weak_cipher_accepted": "B",
        "weak_negotiated_cipher": "B",
        "tls13_missing": "A",
        "hsts_missing": "A",
    }
    return caps.get(code)
