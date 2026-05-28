import json
import logging
import os
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

from shared.tls_audit.adapter import run_full_scan
from shared.tls_audit.archive import create_archive_store
from shared.tls_audit.email_sender import send_email
from shared.tls_audit.jobs import create_job_store
from shared.tls_audit.logging import log_event
from shared.tls_audit.monitor_access import build_monitor_token_secret, create_monitor_owner_token
from shared.tls_audit.monitoring import MonitoringDiff
from shared.tls_audit.monitoring import MonitoringEvent
from shared.tls_audit.monitoring_pipeline import record_monitoring_failure, record_monitoring_report
from shared.tls_audit.monitoring_store import create_monitoring_store
from shared.tls_audit.subscription_store import create_subscription_store
from shared.tls_audit.traffic_control import TargetScanGuard
from shared.tls_audit.validation import validate_worker_target


QUEUE_FILE = os.getenv("DEV_QUEUE_FILE", "/tmp/tls-audit-jobs.jsonl")
QUEUE_NAME = os.getenv("SCAN_QUEUE_NAME", "tls-audit:scan-jobs")
REDIS_URL = os.getenv("REDIS_URL", "")
DATABASE_URL = os.getenv("DATABASE_URL", "")
POLL_SECONDS = float(os.getenv("WORKER_POLL_SECONDS", "1.0"))
TARGET_COOLDOWN_SECONDS = int(os.getenv("TARGET_COOLDOWN_SECONDS", "30"))
ACTIVE_SCAN_TTL_SECONDS = int(os.getenv("ACTIVE_SCAN_TTL_SECONDS", "900"))
ALERT_COOLDOWN_SECONDS = int(os.getenv("ALERT_COOLDOWN_SECONDS", "86400"))
REPORT_COOLDOWN_SECONDS = int(os.getenv("REPORT_COOLDOWN_SECONDS", "43200"))
ALERT_BATCH_COOLDOWN_SECONDS = int(os.getenv("ALERT_BATCH_COOLDOWN_SECONDS", "1800"))
NONCRITICAL_DIGEST_COOLDOWN_SECONDS = int(os.getenv("NONCRITICAL_DIGEST_COOLDOWN_SECONDS", "86400"))
job_store = create_job_store(REDIS_URL)
archive_store = create_archive_store(DATABASE_URL)
monitoring_store = create_monitoring_store(DATABASE_URL)
subscription_store = create_subscription_store(DATABASE_URL)
target_scan_guard = TargetScanGuard(
    redis_url=REDIS_URL,
    cooldown_seconds=TARGET_COOLDOWN_SECONDS,
    active_ttl_seconds=ACTIVE_SCAN_TTL_SECONDS,
)
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("tls_audit.worker")
SCAN_ID_RE = re.compile(r"^[0-9a-f]{32}$")


def handle_job(job: Dict[str, object]) -> Dict[str, object]:
    job_id = str(job.get("id") or "")
    host = str(job["host"])
    port = int(job.get("port") or 443)
    monitored_domain_id = optional_int(job.get("monitored_domain_id"))
    mark_running(job_id)
    log_event(logger, "scan_started", host=host, port=port, job_id=job_id)
    try:
        queued_addresses = queued_job_addresses(job_id, job)
        update_progress(
            job_id,
            3,
            "security",
            "Повторно проверяем DNS и публичность IP перед сканом",
        )
        target = validate_worker_target(host, port, expected_addresses=queued_addresses)
        save_resolved_addresses(job_id, target.addresses)
        report = run_full_scan(
            target.host,
            target.port,
            progress_callback=lambda percent, stage, detail: update_progress(
                job_id, percent, stage, detail
            ),
        )
    except Exception as exc:  # noqa: BLE001 - scanner errors are job state.
        mark_failed(job_id, str(exc))
        record_monitoring_failure(
            monitoring_store,
            monitored_domain_id,
            job_id,
            str(exc),
        )
        send_subscription_failure_report(job, str(exc))
        release_target(job_id, host, port, cooldown=True)
        log_event(
            logger,
            "scan_failed",
            host=host,
            port=port,
            job_id=job_id,
            error=str(exc),
        )
        return {"id": job_id, "status": "error", "error": str(exc)}
    report_dict = report.to_dict()
    result = mark_done(job_id, report_dict)
    monitoring_diff = None
    monitoring_events = []
    if monitored_domain_id:
        _, monitoring_diff, monitoring_events = record_monitoring_report(
            monitoring_store,
            monitored_domain_id,
            job_id,
            report_dict,
        )
    send_subscription_report(job, report_dict, monitoring_diff)
    send_subscription_alert_report(job, monitoring_events, report_dict)
    release_target(job_id, host, port, cooldown=True)
    log_event(logger, "scan_done", host=host, port=port, job_id=job_id)
    return result


def queued_job_addresses(job_id: str, payload: Dict[str, object]) -> list[str]:
    addresses = list(payload.get("addresses") or [])
    if addresses or not job_id:
        return [str(item) for item in addresses]
    stored = job_store.get(job_id)
    return list(stored.addresses) if stored else []


def save_resolved_addresses(job_id: str, addresses: list[str]) -> None:
    if not job_id:
        return
    job = job_store.update(job_id, addresses=addresses)
    if job:
        archive_store.update_scan(job)


def mark_running(job_id: str) -> None:
    if not job_id:
        return
    job = job_store.update(
        job_id,
        status="running",
        progress_percent=1,
        progress_stage="start",
        progress_detail="Worker запустил проверку",
    )
    if job:
        archive_store.update_scan(job)


def update_progress(job_id: str, percent: int, stage: str, detail: str) -> None:
    if not job_id:
        return
    job = job_store.update(
        job_id,
        status="running",
        progress_percent=percent,
        progress_stage=stage,
        progress_detail=detail,
    )
    if job:
        archive_store.update_scan(job)


def mark_done(job_id: str, report: Dict[str, object]) -> Dict[str, object]:
    if job_id:
        job = job_store.update(
            job_id,
            status="done",
            progress_percent=100,
            progress_stage="done",
            progress_detail="Отчёт готов",
            report=report,
            error="",
        )
        if job:
            archive_store.save_report(job)
    return {"id": job_id, "status": "done", "report": report}


def mark_failed(job_id: str, error: str) -> None:
    if not job_id:
        return
    job = job_store.update(
        job_id,
        status="error",
        progress_detail="Проверка завершилась ошибкой",
        error=error,
    )
    if job:
        archive_store.update_scan(job)


def release_target(job_id: str, host: str, port: int, cooldown: bool) -> None:
    if not job_id:
        return
    try:
        target_scan_guard.release(host, port, job_id, cooldown=cooldown)
    except Exception as exc:  # noqa: BLE001 - release TTL will self-heal.
        log_event(
            logger,
            "target_release_failed",
            host=host,
            port=port,
            job_id=job_id,
            error=str(exc),
        )


def optional_int(value: object) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def send_subscription_report(
    job: Dict[str, object],
    report: Dict[str, object],
    monitoring_diff: Optional[MonitoringDiff] = None,
) -> None:
    subscription_id = optional_int(job.get("subscription_id"))
    email = str(job.get("subscription_email") or "").strip()
    plan = str(job.get("subscription_plan") or "free").strip().lower()
    if not subscription_id or not email:
        return
    if plan == "support" and not ownership_verified(subscription_id):
        log_event(
            logger,
            "subscription_report_email_skipped",
            subscription_id=subscription_id,
            email=email,
            reason="ownership_not_verified",
        )
        return
    job_id = str(job.get("id") or "")
    if not job_id:
        return
    if not subscription_store.should_send_report(subscription_id, job_id):
        log_event(
            logger,
            "subscription_report_email_skipped",
            subscription_id=subscription_id,
            email=email,
            reason="duplicate_scan_delivery",
            scan_id=job_id,
        )
        return
    if not subscription_store.should_send_alert(subscription_id, "weekly_report", REPORT_COOLDOWN_SECONDS):
        log_event(
            logger,
            "subscription_report_email_skipped",
            subscription_id=subscription_id,
            email=email,
            reason="report_cooldown_active",
            cooldown_seconds=REPORT_COOLDOWN_SECONDS,
        )
        return
    smtp_url = os.getenv("SMTP_URL", "").strip()
    if not smtp_url:
        log_event(
            logger,
            "subscription_report_email_skipped",
            subscription_id=subscription_id,
            email=email,
            reason="smtp_not_configured",
        )
        return
    host = str(job.get("host") or "")
    port = int(job.get("port") or 443)
    public_base_url = os.getenv("PUBLIC_BASE_URL", "https://tlsaudit.ru").strip().rstrip("/")
    report_link = f"{public_base_url or 'https://tlsaudit.ru'}/scan?job={job_id}"
    grade = str(report.get("grade") or "n/a")
    score = report.get("score")
    cert = report.get("certificate") or {}
    cert_days = cert.get("expires_in_days")
    cert_not_after = cert.get("not_after")
    cert_status = format_certificate_status(cert_days, cert_not_after)
    summary = report.get("summary") or []
    top = summary[0] if isinstance(summary, list) and summary else "Отчёт сформирован."
    highlights = top_findings(report, limit=3)
    subject = f"TLS Audit: еженедельный отчёт {host} — {grade}"
    if plan == "support":
        evidence_block = format_provenance_block(report)
        manage_url, unsubscribe_url = subscription_links(
            subscription_id=subscription_id,
            email=email,
            public_base_url=(public_base_url or "https://tlsaudit.ru"),
        )
        has_public_report_link = bool(SCAN_ID_RE.match(job_id))
        diff_json_url = f"{public_base_url or 'https://tlsaudit.ru'}/api/report/{job_id}/compare"
        diff_ui_url = f"{public_base_url or 'https://tlsaudit.ru'}/scan?job={job_id}#compare-section"
        digest_block = format_pro_digest(monitoring_diff)
        links_block = (
            "\nСсылки:\n"
            + (f"- Scan: {report_link}\n" if has_public_report_link else "")
            + (f"- Diff view: {diff_ui_url}\n" if has_public_report_link else "")
            + (f"- Diff JSON: {diff_json_url}\n" if has_public_report_link else "")
            + f"- Управление подпиской: {manage_url}\n"
            + f"- Отключить подписку: {unsubscribe_url}\n"
        )
        body = (
            "TLS Audit Pro — еженедельный отчёт\n"
            "==================================\n"
            f"Домен: {host}\n"
            f"Порт: {port}\n"
            f"Оценка: {grade}"
            + (f" ({score}/100)\n" if score is not None else "\n")
            + f"Сертификат: {cert_status}\n"
            + format_diff_block(monitoring_diff, detailed=True)
            + digest_block
            + f"Ключевой вывод: {top}\n"
            + (f"\nГлавные замечания:\n{highlights}\n" if highlights else "\n")
            + evidence_block
            + links_block
        )
    else:
        body = (
            "TLS Audit — базовый еженедельный отчёт\n"
            "=====================================\n"
            f"Домен: {host}\n"
            f"Порт: {port}\n"
            f"Оценка: {grade}"
            + (f" ({score}/100)\n" if score is not None else "\n")
            + f"Сертификат: {cert_status}\n"
            + f"Итог: {top}\n"
            + f"Отчёт: {report_link}\n"
        )
    try:
        sent = send_email(
            smtp_url=smtp_url,
            smtp_user=os.getenv("SMTP_USER", "").strip(),
            smtp_password=os.getenv("SMTP_PASSWORD", "").strip(),
            mail_from=os.getenv("ALERT_EMAIL_FROM", "tls-audit@localhost").strip(),
            mail_to=email,
            subject=subject,
            body=body,
        )
        if sent:
            subscription_store.mark_report_sent(subscription_id, job_id)
            subscription_store.mark_sent(subscription_id)
            subscription_store.mark_alert_sent(subscription_id, "weekly_report")
    except Exception as exc:  # noqa: BLE001
        log_event(
            logger,
            "subscription_report_email_failed",
            subscription_id=subscription_id,
            email=email,
            error=str(exc),
        )


def send_subscription_failure_report(job: Dict[str, object], error: str) -> None:
    subscription_id = optional_int(job.get("subscription_id"))
    email = str(job.get("subscription_email") or "").strip()
    plan = str(job.get("subscription_plan") or "free").strip().lower()
    if not subscription_id or not email:
        return
    if not subscription_store.should_send_alert(subscription_id, "scan_failed", ALERT_COOLDOWN_SECONDS):
        return
    smtp_url = os.getenv("SMTP_URL", "").strip()
    if not smtp_url:
        log_event(
            logger,
            "subscription_failure_email_skipped",
            subscription_id=subscription_id,
            email=email,
            reason="smtp_not_configured",
        )
        return
    host = str(job.get("host") or "")
    subject = f"TLS Audit: critical — {host} недоступен"
    if plan == "support":
        body = (
            "TLS Audit Pro — critical alert\n"
            "==============================\n"
            f"Домен: {host}\n"
            "Статус: проверка не завершилась\n"
            f"Причина: {error}\n"
            "Событие помечено как critical. Проверьте доступность сайта, DNS и TLS на сервере.\n"
        )
    else:
        body = (
            "TLS Audit — critical alert\n"
            f"Домен: {host}\n"
            f"Причина: {error}\n"
        )
    try:
        sent = send_email(
            smtp_url=smtp_url,
            smtp_user=os.getenv("SMTP_USER", "").strip(),
            smtp_password=os.getenv("SMTP_PASSWORD", "").strip(),
            mail_from=os.getenv("ALERT_EMAIL_FROM", "tls-audit@localhost").strip(),
            mail_to=email,
            subject=subject,
            body=body,
        )
        if sent:
            subscription_store.mark_alert_sent(subscription_id, "scan_failed")
    except Exception as exc:  # noqa: BLE001
        log_event(
            logger,
            "subscription_failure_email_failed",
            subscription_id=subscription_id,
            email=email,
            error=str(exc),
        )


def send_subscription_alert_report(
    job: Dict[str, object],
    events: list[MonitoringEvent],
    report: Dict[str, object],
) -> None:
    plan = str(job.get("subscription_plan") or "free").strip().lower()
    if plan != "support" or not events:
        return
    interesting_types = {
        "certificate_expiring",
        "certificate_expired",
        "grade_degraded",
        "legacy_tls_enabled",
        "critical_added",
        "scan_failed",
        "high_added",
    }
    interesting = [event for event in events if event.event_type in interesting_types]
    if not interesting:
        return
    immediate_types = {"certificate_expired", "critical_added", "scan_failed"}
    immediate_events = [
        event
        for event in interesting
        if event.event_type in immediate_types or str(event.severity or "").strip().lower() == "critical"
    ]
    digest_events = [
        event
        for event in interesting
        if event not in immediate_events
    ]
    subscription_id = optional_int(job.get("subscription_id"))
    email = str(job.get("subscription_email") or "").strip()
    if not subscription_id or not email:
        return
    if not ownership_verified(subscription_id):
        return
    # Global anti-storm guard for alert batches on the same subscription.
    if not subscription_store.should_send_alert(
        subscription_id,
        "alert_batch",
        ALERT_BATCH_COOLDOWN_SECONDS,
    ):
        log_event(
            logger,
            "subscription_alert_email_skipped",
            subscription_id=subscription_id,
            email=email,
            reason="alert_batch_cooldown_active",
            cooldown_seconds=ALERT_BATCH_COOLDOWN_SECONDS,
        )
        return
    smtp_url = os.getenv("SMTP_URL", "").strip()
    if not smtp_url:
        return
    host = str(job.get("host") or "")
    grade = str(report.get("grade") or "n/a")
    score = report.get("score")
    public_base_url = os.getenv("PUBLIC_BASE_URL", "https://tlsaudit.ru").strip().rstrip("/")
    job_id = str(job.get("id") or "")
    scan_url = f"{public_base_url or 'https://tlsaudit.ru'}/scan?job={job_id}" if job_id else ""
    diff_url = f"{public_base_url or 'https://tlsaudit.ru'}/scan?job={job_id}#compare-section" if job_id else ""
    manage_url, _unsubscribe_url = subscription_links(
        subscription_id=subscription_id,
        email=email,
        public_base_url=(public_base_url or "https://tlsaudit.ru"),
    )
    digest_json_url = owner_digest_json_url(
        email=email,
        public_base_url=(public_base_url or "https://tlsaudit.ru"),
    )
    immediate_pairs: list[tuple[str, MonitoringEvent]] = []
    seen_in_batch: set[str] = set()
    for event in immediate_events:
        alert_key = alert_key_for_event(event)
        if alert_key in seen_in_batch:
            continue
        if subscription_store.should_send_alert(
            subscription_id,
            alert_key,
            alert_cooldown_for_event(event.event_type),
        ):
            seen_in_batch.add(alert_key)
            immediate_pairs.append((alert_key, event))

    if immediate_pairs:
        subject = f"TLS Audit Pro alert: {host} — {immediate_pairs[0][1].title}"
        lines = [
            "TLS Audit Pro — alert",
            "=====================",
            f"Домен: {host}",
            f"Оценка: {grade}" + (f" ({score}/100)" if score is not None else ""),
            "",
            "События:",
        ]
        for _alert_key, event in immediate_pairs:
            detail = f": {event.detail}" if event.detail else ""
            lines.append(f"- [{event.severity.upper()}] {event.title}{detail}")
        if scan_url:
            lines.extend(
                [
                    "",
                    "Ссылки:",
                    f"- Scan: {scan_url}",
                    f"- Diff view: {diff_url}",
                    f"- Управление подпиской: {manage_url}",
                    f"- Owner digest JSON: {digest_json_url}",
                ]
            )
        body = "\n".join(lines) + "\n"
        try:
            sent = send_email(
                smtp_url=smtp_url,
                smtp_user=os.getenv("SMTP_USER", "").strip(),
                smtp_password=os.getenv("SMTP_PASSWORD", "").strip(),
                mail_from=os.getenv("ALERT_EMAIL_FROM", "tls-audit@localhost").strip(),
                mail_to=email,
                subject=subject,
                body=body,
            )
            if sent:
                subscription_store.mark_alert_sent(subscription_id, "alert_batch")
                for alert_key, _event in immediate_pairs:
                    subscription_store.mark_alert_sent(subscription_id, alert_key)
        except Exception as exc:  # noqa: BLE001
            log_event(
                logger,
                "subscription_alert_email_failed",
                subscription_id=subscription_id,
                email=email,
                error=str(exc),
            )

    if digest_events and subscription_store.should_send_alert(
        subscription_id,
        "noncritical_digest",
        NONCRITICAL_DIGEST_COOLDOWN_SECONDS,
    ):
        recent_digest_events = collect_recent_noncritical_events(
            job=job,
            fallback_events=digest_events,
        )
        if recent_digest_events:
            subject = f"TLS Audit Pro digest: {host} — изменения за 24 часа"
            lines = [
                "TLS Audit Pro — digest",
                "=======================",
                f"Домен: {host}",
                f"Оценка: {grade}" + (f" ({score}/100)" if score is not None else ""),
                "",
                "Некритичные изменения (накоплено за 24 часа):",
            ]
            for event in recent_digest_events[:12]:
                detail = f": {event.detail}" if event.detail else ""
                lines.append(f"- [{event.severity.upper()}] {event.title}{detail}")
            if scan_url:
                lines.extend(
                    [
                        "",
                        "Ссылки:",
                        f"- Scan: {scan_url}",
                        f"- Diff view: {diff_url}",
                        f"- Управление подпиской: {manage_url}",
                        f"- Owner digest JSON: {digest_json_url}",
                    ]
                )
            body = "\n".join(lines) + "\n"
            try:
                sent = send_email(
                    smtp_url=smtp_url,
                    smtp_user=os.getenv("SMTP_USER", "").strip(),
                    smtp_password=os.getenv("SMTP_PASSWORD", "").strip(),
                    mail_from=os.getenv("ALERT_EMAIL_FROM", "tls-audit@localhost").strip(),
                    mail_to=email,
                    subject=subject,
                    body=body,
                )
                if sent:
                    subscription_store.mark_alert_sent(subscription_id, "noncritical_digest")
            except Exception as exc:  # noqa: BLE001
                log_event(
                    logger,
                    "subscription_alert_email_failed",
                    subscription_id=subscription_id,
                    email=email,
                    error=str(exc),
                )


def collect_recent_noncritical_events(
    job: Dict[str, object],
    fallback_events: list[MonitoringEvent],
) -> list[MonitoringEvent]:
    monitored_domain_id = optional_int(job.get("monitored_domain_id"))
    if not monitored_domain_id:
        return fallback_events
    rows = monitoring_store.list_events(monitored_domain_id, limit=100)
    if not rows:
        return fallback_events
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    result: list[MonitoringEvent] = []
    allowed_types = {"certificate_expiring", "grade_degraded", "legacy_tls_enabled", "high_added"}
    for row in rows:
        event_type = str(row.get("event_type") or "").strip()
        severity = str(row.get("severity") or "").strip().lower()
        if event_type not in allowed_types:
            continue
        if severity == "critical":
            continue
        created_at = row.get("created_at")
        created_dt = created_at if isinstance(created_at, datetime) else None
        if created_dt is None or created_dt.tzinfo is None:
            continue
        if created_dt < cutoff:
            continue
        result.append(
            MonitoringEvent(
                event_type=event_type,
                severity=severity or "info",
                title=str(row.get("title") or event_type),
                detail=str(row.get("detail") or ""),
                payload=row.get("payload") if isinstance(row.get("payload"), dict) else None,
            )
        )
    if not result:
        return fallback_events
    return result


def alert_cooldown_for_event(event_type: str) -> int:
    normalized = str(event_type or "").strip().lower()
    if normalized == "scan_failed":
        return int(os.getenv("ALERT_SCAN_FAILED_COOLDOWN_SECONDS", "86400"))
    if normalized.startswith("certificate_"):
        return int(os.getenv("ALERT_CERTIFICATE_COOLDOWN_SECONDS", "86400"))
    if normalized in {"grade_degraded", "legacy_tls_enabled", "critical_added"}:
        return int(os.getenv("ALERT_SECURITY_COOLDOWN_SECONDS", "86400"))
    return ALERT_COOLDOWN_SECONDS


def alert_key_for_event(event: MonitoringEvent) -> str:
    event_type = str(event.event_type or "").strip().lower() or "event"
    payload = event.payload or {}
    if event_type == "critical_added":
        code = str(payload.get("code") or "").strip().lower()
        title = str(payload.get("title") or event.title or "").strip().lower()
        if code:
            return f"{event_type}:{code}"
        if title:
            return f"{event_type}:{title}"
    if event_type == "legacy_tls_enabled":
        added = payload.get("added_protocols") or []
        if isinstance(added, list) and added:
            normalized = ",".join(sorted(str(item).strip().upper() for item in added if str(item).strip()))
            if normalized:
                return f"{event_type}:{normalized}"
    if event_type == "grade_degraded":
        delta = payload.get("score_delta")
        if delta is not None:
            return f"{event_type}:{delta}"
    return event_type

def top_findings(report: Dict[str, object], limit: int = 3) -> str:
    items = report.get("findings") or []
    if not isinstance(items, list):
        return ""
    rank = {"critical": 0, "high": 1, "medium": 2, "info": 3}
    grouped: dict[tuple[int, str, str], dict[str, object]] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        severity = str(item.get("severity") or "info").lower()
        title = str(item.get("title") or "").strip()
        detail = str(item.get("detail") or "").strip()
        if not title:
            continue
        key = (rank.get(severity, 9), severity.upper(), title)
        bucket = grouped.setdefault(
            key,
            {"count": 0, "details": []},
        )
        bucket["count"] = int(bucket["count"]) + 1
        if detail:
            details = bucket["details"]
            if isinstance(details, list) and detail not in details and len(details) < 2:
                details.append(detail)
    if not grouped:
        return ""
    ordered = sorted(grouped.items(), key=lambda item: item[0][0])
    lines = []
    for (score_rank, sev, title), payload in ordered[: max(1, int(limit))]:
        del score_rank
        count = int(payload.get("count") or 0)
        details = payload.get("details") if isinstance(payload.get("details"), list) else []
        line = f"- [{sev}] {title}"
        if count > 1:
            line += f" (x{count})"
        if details:
            line += f": {'; '.join(str(item) for item in details)}"
        lines.append(line)
    return "\n".join(lines)


def format_diff_block(diff: Optional[MonitoringDiff], detailed: bool = False) -> str:
    if diff is None:
        return ""
    parts = []
    if diff.grade_improved:
        parts.append("стало лучше")
    elif diff.grade_degraded:
        parts.append("стало хуже")
    elif diff.grade_changed:
        parts.append("оценка изменилась")
    if diff.score_delta:
        sign = "+" if diff.score_delta > 0 else ""
        parts.append(f"баллы: {sign}{diff.score_delta}")
    added = len(diff.added_findings or [])
    resolved = len(diff.resolved_findings or [])
    if added or resolved:
        parts.append(f"новых проблем: {added}, исправлено: {resolved}")
    if detailed:
        if diff.added_findings:
            top_added = ", ".join(item.title for item in diff.added_findings[:2] if item.title)
            if top_added:
                parts.append(f"добавились: {top_added}")
        if diff.resolved_findings:
            top_resolved = ", ".join(item.title for item in diff.resolved_findings[:2] if item.title)
            if top_resolved:
                parts.append(f"исправлены: {top_resolved}")
    if not parts:
        parts.append("без существенных изменений")
    return "Изменения с прошлого скана: " + "; ".join(parts) + ".\n"


def format_certificate_status(cert_days: object, cert_not_after: object) -> str:
    days = optional_int(cert_days)
    not_after = str(cert_not_after or "").strip()
    if days is None:
        return "нет данных"
    if days < 0:
        suffix = f" (истёк {abs(days)} дн. назад)"
        return ("истёк" + suffix + (f", notAfter {not_after}" if not_after else ""))
    if days <= 20:
        suffix = f"осталось {days} дн."
        return (suffix + (f", notAfter {not_after}" if not_after else "") + " — требуется продление")
    return f"осталось {days} дн." + (f" (до {not_after})" if not_after else "")


def format_provenance_block(report: Dict[str, object]) -> str:
    raw = report.get("raw")
    if not isinstance(raw, dict):
        return ""
    provenance = raw.get("provenance")
    if not isinstance(provenance, dict):
        return ""
    sources = provenance.get("sources")
    if not isinstance(sources, list) or not sources:
        return ""
    labels = {
        "basic_scanner": "Базовая TLS-проверка",
        "dns_probe": "Проверка DNS",
        "openssl": "Проверка OpenSSL",
        "http_headers": "Проверка HTTP заголовков",
        "testssl": "Глубокая TLS-проверка",
    }
    lines = ["", "Проверки источников данных:", "--------------------------"]
    for source in sources[:4]:
        if not isinstance(source, dict):
            continue
        source_id = str(source.get("id") or "source").strip()
        source_label = labels.get(source_id, source_id)
        version = str(source.get("version") or "").strip()
        status_raw = str(source.get("status") or "unknown").strip().lower()
        status_ru = "ОК" if status_raw == "done" else ("Ошибка" if status_raw in {"error", "failed"} else "Требует проверки")
        scanned_at = str(source.get("scanned_at") or "").strip()
        line = f"- {source_label}: {status_ru}"
        if version:
            line += f", version={version}"
        if scanned_at:
            line += f", scanned_at={scanned_at}"
        lines.append(line)
    lines.append("- Итог: если везде «ОК», результаты отчёта считаются достоверными.")
    return "\n".join(lines) + "\n"


def subscription_links(subscription_id: int, email: str, public_base_url: str) -> tuple[str, str]:
    manage_url = f"{public_base_url}/monitor-status"
    owner_secret = build_monitor_token_secret(
        monitoring_token_secret=os.getenv("MONITORING_TOKEN_SECRET", ""),
        database_url=os.getenv("DATABASE_URL", ""),
        redis_url=os.getenv("REDIS_URL", ""),
        public_base_url=os.getenv("PUBLIC_BASE_URL", "https://tlsaudit.ru"),
        contact_email=os.getenv("CONTACT_EMAIL", "info@tlsaudit.ru"),
    )
    owner_token = create_monitor_owner_token(email, owner_secret)
    if owner_token:
        manage_url = f"{manage_url}?token={owner_token}"
    unsubscribe_url = f"{public_base_url}/"
    try:
        item = subscription_store.get_by_id(int(subscription_id))
        if item and getattr(item, "token", None):
            unsubscribe_url = f"{public_base_url}/api/subscriptions/monitoring/unsubscribe?token={item.token}"
    except Exception:
        pass
    return manage_url, unsubscribe_url


def owner_digest_json_url(email: str, public_base_url: str) -> str:
    owner_secret = build_monitor_token_secret(
        monitoring_token_secret=os.getenv("MONITORING_TOKEN_SECRET", ""),
        database_url=os.getenv("DATABASE_URL", ""),
        redis_url=os.getenv("REDIS_URL", ""),
        public_base_url=os.getenv("PUBLIC_BASE_URL", "https://tlsaudit.ru"),
        contact_email=os.getenv("CONTACT_EMAIL", "info@tlsaudit.ru"),
    )
    owner_token = create_monitor_owner_token(email, owner_secret)
    return f"{public_base_url}/api/subscriptions/monitoring/digest.json?token={owner_token}"


def format_pro_digest(diff: Optional[MonitoringDiff]) -> str:
    if diff is None:
        return ""
    added = [item for item in (diff.added_findings or []) if str(item.severity).lower() in {"critical", "high"}]
    resolved = [item for item in (diff.resolved_findings or []) if str(item.severity).lower() in {"critical", "high"}]
    if not added and not resolved:
        return "Digest: критичных/high изменений не обнаружено.\n"
    lines = ["Digest (critical/high):"]
    if added:
        lines.append("- Добавились: " + "; ".join(item.title for item in added[:3] if item.title))
    if resolved:
        lines.append("- Ушли: " + "; ".join(item.title for item in resolved[:3] if item.title))
    return "\n".join(lines) + "\n"


def ownership_verified(subscription_id: int) -> bool:
    try:
        item = subscription_store.get_by_id(int(subscription_id))
    except Exception:
        return False
    if not item:
        return False
    return getattr(item, "ownership_verified_at", None) is not None


def run_dev_file_worker() -> None:
    print(f"TLS Audit dev worker watching {QUEUE_FILE}")
    while True:
        if not os.path.exists(QUEUE_FILE):
            time.sleep(POLL_SECONDS)
            continue
        with open(QUEUE_FILE, "r", encoding="utf-8") as source:
            jobs = [json.loads(line) for line in source if line.strip()]
        open(QUEUE_FILE, "w", encoding="utf-8").close()
        for job in jobs:
            result = handle_job(job)
            print(json.dumps(result, ensure_ascii=False))


def run_redis_worker() -> None:
    import redis

    client = redis.from_url(REDIS_URL)
    print(f"TLS Audit worker listening on Redis queue {QUEUE_NAME}")
    while True:
        _queue, payload = client.blpop(QUEUE_NAME)
        job = json.loads(payload)
        handle_job(job)


if __name__ == "__main__":
    if REDIS_URL:
        run_redis_worker()
    else:
        run_dev_file_worker()
