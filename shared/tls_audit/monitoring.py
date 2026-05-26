from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set


@dataclass
class FindingSummary:
    code: str
    title: str
    severity: str
    category: str

    @property
    def key(self) -> str:
        return "|".join([self.code, self.title, self.severity, self.category])

    def to_dict(self) -> Dict[str, str]:
        return {
            "code": self.code,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
        }


@dataclass
class MonitoringSnapshot:
    monitored_domain_id: int
    scan_id: str
    grade: Optional[str] = None
    score: Optional[int] = None
    certificate_not_after: Optional[str] = None
    certificate_expires_in_days: Optional[int] = None
    supported_protocols: List[str] = field(default_factory=list)
    hsts: Dict[str, object] = field(default_factory=dict)
    findings: List[FindingSummary] = field(default_factory=list)
    created_at: Optional[datetime] = None
    id: Optional[int] = None

    def finding_keys(self) -> Set[str]:
        return {finding.key for finding in self.findings}

    def finding_by_key(self) -> Dict[str, FindingSummary]:
        return {finding.key: finding for finding in self.findings}


@dataclass
class MonitoringDiff:
    grade_changed: bool = False
    grade_degraded: bool = False
    grade_improved: bool = False
    score_delta: Optional[int] = None
    certificate_expiring: bool = False
    certificate_expired: bool = False
    supported_protocols_added: List[str] = field(default_factory=list)
    supported_protocols_removed: List[str] = field(default_factory=list)
    hsts_changed: bool = False
    added_findings: List[FindingSummary] = field(default_factory=list)
    resolved_findings: List[FindingSummary] = field(default_factory=list)


@dataclass
class MonitoringEvent:
    event_type: str
    severity: str
    title: str
    detail: str = ""
    payload: Dict[str, object] = field(default_factory=dict)


GRADE_RANK = {"A+": 5, "A": 4, "B": 3, "C": 2, "D": 1}
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def snapshot_from_report(
    monitored_domain_id: int,
    scan_id: str,
    report: Dict[str, object],
) -> MonitoringSnapshot:
    certificate = dict(report.get("certificate") or {})
    protocols = dict(report.get("protocols") or {})
    hsts = dict(report.get("hsts") or {})
    return MonitoringSnapshot(
        monitored_domain_id=monitored_domain_id,
        scan_id=scan_id,
        grade=optional_str(report.get("grade")),
        score=optional_int(report.get("score")),
        certificate_not_after=optional_str(certificate.get("not_after")),
        certificate_expires_in_days=optional_int(certificate.get("expires_in_days")),
        supported_protocols=supported_protocol_versions(protocols),
        hsts=hsts_summary(hsts),
        findings=summarize_findings(list(report.get("findings") or [])),
    )


def diff_snapshots(
    current: MonitoringSnapshot,
    previous: Optional[MonitoringSnapshot],
    certificate_warning_days: int = 20,
) -> MonitoringDiff:
    if previous is None:
        return MonitoringDiff(
            certificate_expiring=is_expiring(current, certificate_warning_days),
            certificate_expired=is_expired(current),
            added_findings=sorted_findings(current.findings),
        )

    current_findings = current.finding_by_key()
    previous_findings = previous.finding_by_key()
    current_keys = set(current_findings)
    previous_keys = set(previous_findings)
    score_delta = None
    if current.score is not None and previous.score is not None:
        score_delta = current.score - previous.score

    return MonitoringDiff(
        grade_changed=current.grade != previous.grade,
        grade_degraded=grade_rank(current.grade) < grade_rank(previous.grade),
        grade_improved=grade_rank(current.grade) > grade_rank(previous.grade),
        score_delta=score_delta,
        certificate_expiring=certificate_crossed_expiring_threshold(
            current,
            previous,
            certificate_warning_days,
        ),
        certificate_expired=is_expired(current) and not is_expired(previous),
        supported_protocols_added=sorted(
            set(current.supported_protocols) - set(previous.supported_protocols)
        ),
        supported_protocols_removed=sorted(
            set(previous.supported_protocols) - set(current.supported_protocols)
        ),
        hsts_changed=current.hsts != previous.hsts,
        added_findings=sorted_findings(
            [current_findings[key] for key in current_keys - previous_keys]
        ),
        resolved_findings=sorted_findings(
            [previous_findings[key] for key in previous_keys - current_keys]
        ),
    )


def events_from_diff(diff: MonitoringDiff) -> List[MonitoringEvent]:
    events: List[MonitoringEvent] = []
    if diff.grade_degraded:
        score_detail = ""
        if diff.score_delta is not None:
            score_detail = f"Изменение баллов: {diff.score_delta}."
        events.append(
            MonitoringEvent(
                event_type="grade_degraded",
                severity="high",
                title="Оценка TLS ухудшилась",
                detail=score_detail,
                payload={"score_delta": diff.score_delta},
            )
        )
    elif diff.grade_improved:
        events.append(
            MonitoringEvent(
                event_type="grade_improved",
                severity="info",
                title="Оценка TLS улучшилась",
                payload={"score_delta": diff.score_delta},
            )
        )

    if diff.certificate_expired:
        events.append(
            MonitoringEvent(
                event_type="certificate_expired",
                severity="critical",
                title="Сертификат истёк",
            )
        )
    elif diff.certificate_expiring:
        events.append(
            MonitoringEvent(
                event_type="certificate_expiring",
                severity="high",
                title="Сертификат скоро истекает",
            )
        )

    for finding in diff.added_findings:
        if finding.severity == "critical":
            events.append(finding_event("critical_added", finding))
        elif finding.severity == "high":
            events.append(finding_event("high_added", finding))

    for finding in diff.resolved_findings:
        if finding.severity in {"critical", "high"}:
            events.append(
                MonitoringEvent(
                    event_type="finding_resolved",
                    severity="info",
                    title="Серьёзное замечание устранено",
                    detail=finding.title,
                    payload=finding.to_dict(),
                )
            )

    if "TLS 1.0" in diff.supported_protocols_added or "TLS 1.1" in diff.supported_protocols_added:
        added = ", ".join(diff.supported_protocols_added)
        events.append(
            MonitoringEvent(
                event_type="legacy_tls_enabled",
                severity="high",
                title="Включился устаревший TLS",
                detail=f"Добавлены протоколы: {added}" if added else "",
                payload={"added_protocols": diff.supported_protocols_added},
            )
        )

    if diff.hsts_changed:
        events.append(
            MonitoringEvent(
                event_type="hsts_changed",
                severity="medium",
                title="Изменилась HSTS-конфигурация",
            )
        )

    return events


def scan_failed_event(error: str) -> MonitoringEvent:
    return MonitoringEvent(
        event_type="scan_failed",
        severity="critical",
        title="Сайт недоступен или TLS-проверка не завершилась",
        detail=error,
    )


def scan_failed_events(error: str) -> List[MonitoringEvent]:
    return [scan_failed_event(error)]


def supported_protocol_versions(protocols: Dict[str, object]) -> List[str]:
    items = list(protocols.get("items") or [])
    supported = [
        str(item.get("version"))
        for item in items
        if isinstance(item, dict) and item.get("supported") and item.get("version")
    ]
    return sorted(set(supported), key=protocol_sort_key)


def summarize_findings(items: List[Dict[str, object]]) -> List[FindingSummary]:
    seen: Dict[str, FindingSummary] = {}
    for item in items:
        finding = FindingSummary(
            code=str(item.get("code") or "unknown"),
            title=str(item.get("title") or item.get("code") or "Finding"),
            severity=str(item.get("severity") or "info"),
            category=str(item.get("category") or "general"),
        )
        seen.setdefault(finding.key, finding)
    return sorted_findings(list(seen.values()))


def hsts_summary(hsts: Dict[str, object]) -> Dict[str, object]:
    return {
        "enabled": bool(hsts.get("hsts")),
        "max_age": optional_int(hsts.get("hsts_max_age")),
        "include_subdomains": bool(hsts.get("hsts_include_subdomains")),
        "preload": bool(hsts.get("hsts_preload")),
    }


def finding_event(event_type: str, finding: FindingSummary) -> MonitoringEvent:
    return MonitoringEvent(
        event_type=event_type,
        severity=finding.severity,
        title=finding.title,
        detail=finding.code,
        payload=finding.to_dict(),
    )


def is_expiring(snapshot: MonitoringSnapshot, warning_days: int) -> bool:
    days = snapshot.certificate_expires_in_days
    return days is not None and 0 <= days <= warning_days


def is_expired(snapshot: MonitoringSnapshot) -> bool:
    days = snapshot.certificate_expires_in_days
    return days is not None and days < 0


def certificate_crossed_expiring_threshold(
    current: MonitoringSnapshot,
    previous: MonitoringSnapshot,
    warning_days: int,
) -> bool:
    return is_expiring(current, warning_days) and not is_expiring(previous, warning_days)


def grade_rank(grade: Optional[str]) -> int:
    return GRADE_RANK.get(str(grade or ""), 0)


def sorted_findings(findings: List[FindingSummary]) -> List[FindingSummary]:
    return sorted(
        findings,
        key=lambda item: (
            -SEVERITY_RANK.get(item.severity, 0),
            item.category,
            item.code,
            item.title,
        ),
    )


def protocol_sort_key(version: str) -> tuple:
    order = {
        "SSL 2.0": 0,
        "SSL 3.0": 1,
        "TLS 1.0": 2,
        "TLS 1.1": 3,
        "TLS 1.2": 4,
        "TLS 1.3": 5,
    }
    return (order.get(version, 99), version)


def optional_int(value: object) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def optional_str(value: object) -> Optional[str]:
    if value is None:
        return None
    text = str(value)
    return text if text else None
