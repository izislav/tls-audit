import json
import os
import signal
import shutil
import subprocess
import tempfile
import time
from typing import Any, Callable, Dict, List, Optional

from .recommendations import (
    BREACH_FIX,
    LUCKY13_FIX,
    OCSP_STAPLING_FIX,
    SECURE_CIPHERS,
    TLS12_13_ONLY,
    VULNERABILITY_FIX,
)
from .report import Finding, Report
from .russian_trust import analyze_russian_tls
from .scoring import score_report


TESTSSL_TIMEOUT_SECONDS = int(
    os.getenv("TESTSSL_TIMEOUT_SECONDS", os.getenv("MAX_SCAN_SECONDS", "60"))
)
TESTSSL_COMMAND = os.getenv("TESTSSL_COMMAND", "testssl")
TESTSSL_OPENSSL_TIMEOUT = os.getenv("TESTSSL_OPENSSL_TIMEOUT", "5")

SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "WARN": "low",
    "INFO": "info",
    "OK": "info",
}

PROTOCOL_NAMES = {
    "SSLv2": "SSLv2",
    "SSLv3": "SSLv3",
    "TLS1": "TLS 1.0",
    "TLS1_1": "TLS 1.1",
    "TLS1_2": "TLS 1.2",
    "TLS1_3": "TLS 1.3",
}


def run_testssl_scan(
    host: str,
    port: int = 443,
    timeout_seconds: int = TESTSSL_TIMEOUT_SECONDS,
    progress_callback: Optional[Callable[[int, str, str], None]] = None,
) -> Dict[str, Any]:
    command = shutil.which(TESTSSL_COMMAND)
    if not command:
        return {
            "enabled": False,
            "error": "Модуль глубокой TLS-проверки недоступен в worker.",
        }

    target = f"https://{host}:{port}"
    if progress_callback:
        progress_callback(90, "deep_tls", "Запускаем глубокую TLS-проверку")

    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="tls-audit-testssl-") as workdir:
        json_path = os.path.join(workdir, "testssl.json")
        args = [
            command,
            "--quiet",
            "--warnings",
            "batch",
            "--openssl-timeout",
            TESTSSL_OPENSSL_TIMEOUT,
            "--color",
            "0",
            "--ids-friendly",
            "-S",
            "-p",
            "-E",
            "-U",
            "--jsonfile-pretty",
            json_path,
            target,
        ]
        process = subprocess.Popen(
            args,
            cwd=workdir,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )
        try:
            stdout, _stderr = process.communicate(timeout=timeout_seconds)
            returncode = process.returncode
        except subprocess.TimeoutExpired:
            stdout = terminate_process_group(process)
            return {
                "enabled": True,
                "timeout": True,
                "error": (
                    f"Глубокая TLS-проверка не завершилась за "
                    f"{timeout_seconds} секунд."
                ),
                "stdout_tail": tail(stdout or ""),
                "duration_seconds": round(time.monotonic() - started, 2),
            }

        payload: Dict[str, Any] = {
            "enabled": True,
            "command": " ".join(args[:-2] + ["<jsonfile>", target]),
            "exit_code": returncode,
            "duration_seconds": round(time.monotonic() - started, 2),
            "stdout_tail": tail(stdout),
        }
        if os.path.exists(json_path):
            with open(json_path, "r", encoding="utf-8") as source:
                payload["json"] = json.load(source)
        else:
            payload["error"] = (
                "Глубокая TLS-проверка не вернула структурированный результат."
            )
        return payload


def terminate_process_group(process: subprocess.Popen) -> str:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        stdout, _stderr = process.communicate(timeout=3)
        return stdout or ""
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        stdout, _stderr = process.communicate()
        return stdout or ""


def merge_testssl_result(report: Report, result: Dict[str, Any]) -> Report:
    report.raw["testssl"] = result
    if not result.get("enabled"):
        report.vulnerabilities = {
            **report.vulnerabilities,
            "testssl_status": "disabled",
            "testssl_error": result.get("error", ""),
        }
        return score_report(report)

    payload = result.get("json")
    scan = first_scan_result(payload)
    if not scan:
        report.vulnerabilities = {
            **report.vulnerabilities,
            "testssl_status": "error",
            "testssl_error": result.get("error")
            or "Глубокая TLS-проверка не вернула результат.",
        }
        return score_report(report)

    protocol_items = scan.get("protocols") or []
    vulnerability_items = scan.get("vulnerabilities") or []
    report.protocols["testssl"] = protocol_items
    report.cipher_suites["testssl_cipher_tests"] = scan.get("cipherTests") or []
    report.cipher_suites["testssl_server_preferences"] = scan.get("serverPreferences") or []
    report.cipher_suites["testssl_forward_secrecy"] = scan.get("fs") or []
    report.vulnerabilities = normalize_vulnerabilities(
        vulnerability_items, protocol_items
    )
    report.ocsp = extract_ocsp(scan.get("serverDefaults") or [])
    report.chain = {**report.chain, **extract_chain(scan.get("serverDefaults") or [])}
    report.raw["testssl_summary"] = {
        "version": payload.get("version") if isinstance(payload, dict) else "",
        "scan_time": payload.get("scanTime") if isinstance(payload, dict) else "",
        "target_ip": scan.get("ip"),
    }
    report.findings.extend(findings_from_testssl(scan))
    report.russian_tls = analyze_russian_tls(report)
    return score_report(report)


def first_scan_result(payload: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(payload, dict):
        return None
    results = payload.get("scanResult")
    if isinstance(results, list) and results and isinstance(results[0], dict):
        return results[0]
    return None


def normalize_vulnerabilities(
    items: List[Dict[str, Any]], protocols: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    normalized = [
        normalize_vulnerability_item(item, protocols or []) for item in items
    ]
    problems = [
        item
        for item in normalized
        if severity_for(item.get("severity")) in {"critical", "high", "medium", "low"}
    ]
    return {
        "testssl_status": "done",
        "items": normalized,
        "problems": problems,
        "problem_count": len(problems),
    }


def normalize_vulnerability_item(
    item: Dict[str, Any], protocols: List[Dict[str, Any]]
) -> Dict[str, Any]:
    if not is_lucky13(item) or not lucky13_is_closed_by_protocols(protocols):
        return item

    normalized = dict(item)
    normalized["original_severity"] = item.get("severity", "")
    normalized["severity"] = "INFO"
    finding = str(item.get("finding") or "")
    note = (
        "Баллы не снимаются: TLS 1.0 и TLS 1.1 не предлагаются, поэтому риск "
        "Lucky13 для старых протоколов закрыт."
    )
    normalized["finding"] = f"{finding}. {note}" if finding else note
    return normalized


def extract_ocsp(server_defaults: List[Dict[str, Any]]) -> Dict[str, Any]:
    ocsp_items = [
        item
        for item in server_defaults
        if "ocsp" in str(item.get("id", "")).lower()
        or "ocsp" in str(item.get("finding", "")).lower()
    ]
    return {
        "testssl_items": ocsp_items,
        "status": ocsp_status(ocsp_items),
    }


def ocsp_status(items: List[Dict[str, Any]]) -> str:
    if not items:
        return "not_reported"
    stapling = next(
        (item for item in items if str(item.get("id", "")).lower() == "ocsp_stapling"),
        None,
    )
    if not stapling:
        return "checked"
    finding = str(stapling.get("finding") or "").lower()
    if "not offered" in finding or "--" == finding.strip():
        return "not_offered"
    return "offered"


def extract_chain(server_defaults: List[Dict[str, Any]]) -> Dict[str, Any]:
    wanted_prefixes = (
        "cert_trust",
        "cert_chain",
        "certs_",
        "intermediate_cert",
        "cert_caissuers",
        "cert_ocspurl",
        "cert_crldistributionpoints",
    )
    items = [
        item
        for item in server_defaults
        if str(item.get("id", "")).lower().startswith(wanted_prefixes)
        and not is_pem_item(item)
    ]
    return {
        "testssl_items": items,
        "status": "checked" if items else "not_reported",
    }


def is_pem_item(item: Dict[str, Any]) -> bool:
    finding = str(item.get("finding") or "")
    return finding.lstrip().startswith("-----BEGIN CERTIFICATE-----")


def findings_from_testssl(scan: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    protocols = scan.get("protocols") or []
    findings.extend(protocol_findings(protocols))
    findings.extend(vulnerability_findings(scan.get("vulnerabilities") or [], protocols))
    findings.extend(ocsp_findings(scan.get("serverDefaults") or []))
    findings.extend(forward_secrecy_findings(scan.get("fs") or []))
    return findings


def protocol_findings(items: List[Dict[str, Any]]) -> List[Finding]:
    findings: List[Finding] = []
    for item in items:
        protocol_id = str(item.get("id") or "")
        name = PROTOCOL_NAMES.get(protocol_id)
        if not name:
            continue
        finding_text = str(item.get("finding") or "").lower()
        if "not offered" in finding_text:
            continue
        if protocol_id in {"SSLv2", "SSLv3"}:
            findings.append(
                Finding(
                    severity="critical",
                    code="insecure_protocol",
                    category="tls",
                    title=f"Включён небезопасный протокол {name}",
                    detail=f"{name}: {item.get('finding')}",
                    recommendation=TLS12_13_ONLY,
                    evidence={"source": "testssl", "id": protocol_id},
                    grade_cap="D",
                )
            )
        elif protocol_id in {"TLS1", "TLS1_1"}:
            findings.append(
                Finding(
                    severity="high",
                    code="legacy_tls",
                    category="tls",
                    title="Включён устаревший TLS",
                    detail=f"{name}: {item.get('finding')}",
                    recommendation=TLS12_13_ONLY,
                    evidence={"source": "testssl", "id": protocol_id},
                    grade_cap="B",
                )
            )
    return findings


def vulnerability_findings(
    items: List[Dict[str, Any]], protocols: Optional[List[Dict[str, Any]]] = None
) -> List[Finding]:
    findings: List[Finding] = []
    for item in items:
        effective = normalize_vulnerability_item(item, protocols or [])
        severity = severity_for(effective.get("severity"))
        if severity not in {"critical", "high", "medium", "low", "info"}:
            continue
        vuln_id = str(effective.get("id") or "testssl_vulnerability")
        if severity == "info" and not is_lucky13(effective):
            continue
        title = title_for_vulnerability(vuln_id)
        findings.append(
            Finding(
                severity=severity,
                code=f"testssl_{vuln_id.lower()}",
                category="vulnerabilities",
                title=title,
                detail=str(effective.get("finding") or ""),
                recommendation=recommendation_for_vulnerability(vuln_id),
                evidence={
                    "source": "testssl",
                    "id": vuln_id,
                    "cve": effective.get("cve", ""),
                    "cwe": effective.get("cwe", ""),
                    "severity": effective.get("severity", ""),
                    "original_severity": effective.get("original_severity", ""),
                },
                grade_cap=grade_cap_for_vulnerability(vuln_id, severity),
            )
        )
    return findings


def is_lucky13(item: Dict[str, Any]) -> bool:
    return str(item.get("id") or "").upper() == "LUCKY13"


def lucky13_is_closed_by_protocols(protocols: List[Dict[str, Any]]) -> bool:
    tls10 = protocol_by_id(protocols, "TLS1")
    tls11 = protocol_by_id(protocols, "TLS1_1")
    if not tls10 or not tls11:
        return False
    return protocol_not_offered(tls10) and protocol_not_offered(tls11)


def protocol_by_id(
    protocols: List[Dict[str, Any]], protocol_id: str
) -> Optional[Dict[str, Any]]:
    return next(
        (
            item
            for item in protocols
            if isinstance(item, dict) and str(item.get("id") or "") == protocol_id
        ),
        None,
    )


def protocol_not_offered(item: Dict[str, Any]) -> bool:
    return "not offered" in str(item.get("finding") or "").lower()


def ocsp_findings(server_defaults: List[Dict[str, Any]]) -> List[Finding]:
    findings: List[Finding] = []
    for item in server_defaults:
        if str(item.get("id", "")).lower() != "ocsp_stapling":
            continue
        status = ocsp_status([item])
        if status == "not_offered":
            findings.append(
                Finding(
                    severity="info",
                    code="ocsp_stapling_missing",
                    category="ocsp",
                    title="OCSP stapling не включен",
                    detail=(
                        f"{item.get('finding') or 'not offered'}. "
                        "Это полезная оптимизация проверки отзыва, но не критическая TLS-уязвимость."
                    ),
                    recommendation=OCSP_STAPLING_FIX,
                    evidence={"source": "testssl", "id": item.get("id", "")},
                )
            )
    return findings


def forward_secrecy_findings(items: List[Dict[str, Any]]) -> List[Finding]:
    findings: List[Finding] = []
    for item in items:
        severity = severity_for(item.get("severity"))
        if severity not in {"critical", "high", "medium", "low"}:
            continue
        findings.append(
            Finding(
                severity=severity,
                code=f"testssl_{str(item.get('id') or 'forward_secrecy').lower()}",
                category="cipher",
                title="Замечание по forward secrecy / DH / EC",
                detail=str(item.get("finding") or ""),
                recommendation=SECURE_CIPHERS,
                evidence={
                    "source": "testssl",
                    "id": item.get("id", ""),
                    "severity": item.get("severity", ""),
                },
                grade_cap=grade_cap_for_forward_secrecy(severity),
            )
        )
    return findings


def recommendation_for_vulnerability(vuln_id: str):
    normalized = vuln_id.upper()
    if normalized == "BREACH":
        return BREACH_FIX
    if normalized == "LUCKY13":
        return LUCKY13_FIX
    return VULNERABILITY_FIX


def title_for_vulnerability(vuln_id: str) -> str:
    known = {
        "BREACH": "Возможен BREACH из-за HTTP compression",
        "CRIME_TLS": "Обнаружен риск CRIME/TLS compression",
        "POODLE_SSL": "Обнаружен риск POODLE",
        "SWEET32": "Обнаружен риск SWEET32",
        "FREAK": "Обнаружен риск FREAK",
        "DROWN": "Обнаружен риск DROWN",
        "LOGJAM": "Обнаружен риск LOGJAM",
        "ROBOT": "Обнаружен риск ROBOT",
        "heartbleed": "Обнаружен риск Heartbleed",
        "LUCKY13": "Напоминание о CBC suites / Lucky13",
    }
    return known.get(vuln_id, f"Дополнительная проверка: {vuln_id}")


def grade_cap_for_vulnerability(vuln_id: str, severity: str) -> Optional[str]:
    if vuln_id.upper() in {"BREACH", "LUCKY13"}:
        return None
    return {
        "critical": "D",
        "high": "D",
    }.get(severity)


def grade_cap_for_forward_secrecy(severity: str) -> Optional[str]:
    return {
        "critical": "D",
        "high": "C",
    }.get(severity)


def severity_for(value: Any) -> str:
    return SEVERITY_MAP.get(str(value or "").upper(), "info")


def tail(text: str, max_lines: int = 60) -> str:
    lines = str(text or "").splitlines()
    return "\n".join(lines[-max_lines:])
