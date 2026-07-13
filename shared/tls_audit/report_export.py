import csv
import io
from collections import Counter
from typing import Any, Dict, Optional

from .compare import summarize_report


def report_digest_payload(
    job_id: str,
    report: Dict[str, Any],
    scan: Optional[Dict[str, Any]] = None,
    public_base_url: str = "https://tlsaudit.ru",
) -> Dict[str, Any]:
    scan = scan or {}
    base_url = (public_base_url or "https://tlsaudit.ru").rstrip("/")
    summary = summarize_report(job_id, report, scan)
    findings = list(report.get("findings") or [])
    severity_counts = Counter(str(item.get("severity") or "info").lower() for item in findings if isinstance(item, dict))
    top_findings_by_key: Dict[tuple[str, str], Dict[str, Any]] = {}
    for item in findings:
        if not isinstance(item, dict):
            continue
        key = (str(item.get("code") or ""), str(item.get("title") or ""))
        existing = top_findings_by_key.get(key)
        if existing:
            existing["count"] += 1
            continue
        top_findings_by_key[key] = {
            "code": item.get("code"),
            "title": item.get("title"),
            "severity": item.get("severity"),
            "category": item.get("category"),
            "grade_cap": item.get("grade_cap"),
            "count": 1,
        }
    top_findings = list(top_findings_by_key.values())
    recommendations = list(report.get("recommendations") or [])
    cert = dict(report.get("certificate") or {})
    hsts = dict(report.get("hsts") or {})
    return {
        "id": summary.get("id") or job_id,
        "host": summary.get("host"),
        "port": summary.get("port") or 443,
        "grade": summary.get("grade"),
        "score": summary.get("score"),
        "summary": list(report.get("summary") or []),
        "certificate": {
            "subject": cert.get("subject"),
            "issuer": cert.get("issuer"),
            "expires_in_days": cert.get("expires_in_days"),
            "not_after": cert.get("not_after"),
            "expired": cert.get("expired"),
        },
        "hsts": {
            "enabled": hsts.get("hsts"),
            "max_age": hsts.get("hsts_max_age"),
            "include_subdomains": hsts.get("hsts_include_subdomains"),
            "preload": hsts.get("hsts_preload"),
        },
        "severity_counts": {
            "critical": int(severity_counts.get("critical", 0)),
            "high": int(severity_counts.get("high", 0)),
            "medium": int(severity_counts.get("medium", 0)),
            "low": int(severity_counts.get("low", 0)),
            "info": int(severity_counts.get("info", 0)),
        },
        "top_findings": top_findings[:5],
        "top_recommendations": recommendations[:3],
        "links": {
            "scan": f"{base_url}/scan?job={job_id}",
            "compare": f"{base_url}/scan?job={job_id}#compare-section",
            "raw_json": f"{base_url}/api/report/{job_id}",
            "csv": f"{base_url}/api/report/{job_id}/export.csv",
        },
    }


def report_digest_to_csv(
    job_id: str,
    report: Dict[str, Any],
    scan: Optional[Dict[str, Any]] = None,
    public_base_url: str = "https://tlsaudit.ru",
) -> str:
    digest = report_digest_payload(job_id, report, scan, public_base_url)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "id",
            "host",
            "port",
            "grade",
            "score",
            "cert_expires_in_days",
            "critical",
            "high",
            "medium",
            "low",
            "info",
            "top_findings",
            "top_recommendations",
            "scan_url",
            "compare_url",
        ]
    )
    writer.writerow(
        [
            digest.get("id") or job_id,
            digest.get("host") or "",
            digest.get("port") or 443,
            digest.get("grade") or "",
            digest.get("score") if digest.get("score") is not None else "",
            digest.get("certificate", {}).get("expires_in_days") if digest.get("certificate") else "",
            digest.get("severity_counts", {}).get("critical", 0),
            digest.get("severity_counts", {}).get("high", 0),
            digest.get("severity_counts", {}).get("medium", 0),
            digest.get("severity_counts", {}).get("low", 0),
            digest.get("severity_counts", {}).get("info", 0),
            " | ".join(item.get("title", "") for item in digest.get("top_findings", [])),
            " | ".join(str(item) for item in digest.get("top_recommendations", [])[:3]),
            digest.get("links", {}).get("scan", ""),
            digest.get("links", {}).get("compare", ""),
        ]
    )
    return output.getvalue()
