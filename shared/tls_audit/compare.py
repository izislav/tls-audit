from datetime import date, datetime
from typing import Any, Dict, List, Optional


def summarize_report(
    scan_id: str,
    report: Dict[str, Any],
    scan: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    scan = scan or {}
    return {
        "id": scan_id,
        "host": report.get("host") or scan.get("host"),
        "port": report.get("port") or scan.get("port") or 443,
        "grade": report.get("grade") or scan.get("grade"),
        "score": report.get("score") if report.get("score") is not None else scan.get("score"),
        "created_at": normalize_datetime(scan.get("created_at")),
        "finished_at": normalize_datetime(scan.get("finished_at")),
        "findings": summarize_findings(report.get("findings") or []),
    }


def compare_reports(
    current: Dict[str, Any],
    previous: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    if not previous:
        return {
            "has_previous": False,
            "grade_changed": False,
            "score_delta": None,
            "resolved_findings": [],
            "added_findings": [],
            "unchanged_findings_count": len(current.get("findings") or []),
        }

    current_findings = keyed_findings(current.get("findings") or [])
    previous_findings = keyed_findings(previous.get("findings") or [])
    current_keys = set(current_findings)
    previous_keys = set(previous_findings)

    return {
        "has_previous": True,
        "grade_changed": current.get("grade") != previous.get("grade"),
        "score_delta": numeric_delta(current.get("score"), previous.get("score")),
        "resolved_findings": sorted(
            [previous_findings[key] for key in previous_keys - current_keys],
            key=finding_sort_key,
        ),
        "added_findings": sorted(
            [current_findings[key] for key in current_keys - previous_keys],
            key=finding_sort_key,
        ),
        "unchanged_findings_count": len(current_keys & previous_keys),
    }


def summarize_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = {}
    for item in findings:
        code = str(item.get("code") or "unknown")
        title = str(item.get("title") or code)
        severity = str(item.get("severity") or "info")
        category = str(item.get("category") or "general")
        key = f"{code}|{title}|{severity}|{category}"
        if key not in seen:
            seen[key] = {
                "code": code,
                "title": title,
                "severity": severity,
                "category": category,
            }
    return list(seen.values())


def keyed_findings(findings: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    return {
        f"{item.get('code')}|{item.get('title')}|{item.get('severity')}|{item.get('category')}": item
        for item in findings
    }


def numeric_delta(current: Any, previous: Any) -> Optional[float]:
    if current is None or previous is None:
        return None
    try:
        return float(current) - float(previous)
    except (TypeError, ValueError):
        return None


def normalize_datetime(value: Any) -> Any:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return value


def finding_sort_key(item: Dict[str, Any]) -> tuple:
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return (
        severity_order.get(str(item.get("severity") or "info"), 9),
        str(item.get("category") or ""),
        str(item.get("code") or ""),
    )
