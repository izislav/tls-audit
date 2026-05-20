import json
import logging
import os
import time
from typing import Dict, Optional

from shared.tls_audit.adapter import run_full_scan
from shared.tls_audit.archive import create_archive_store
from shared.tls_audit.email_sender import send_email
from shared.tls_audit.jobs import create_job_store
from shared.tls_audit.logging import log_event
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
    job_id = str(job.get("id") or "")
    public_base_url = os.getenv("PUBLIC_BASE_URL", "https://tlsaudit.ru").strip().rstrip("/")
    report_link = f"{public_base_url or 'https://tlsaudit.ru'}/scan?job={job_id}"
    grade = str(report.get("grade") or "n/a")
    score = report.get("score")
    cert = report.get("certificate") or {}
    cert_days = cert.get("expires_in_days")
    cert_not_after = cert.get("not_after")
    summary = report.get("summary") or []
    top = summary[0] if isinstance(summary, list) and summary else "Отчёт сформирован."
    highlights = top_findings(report, limit=3)
    subject = f"TLS Audit: еженедельный отчёт {host} — {grade}"
    if plan == "support":
        body = (
            "TLS Audit Pro — еженедельный отчёт\n"
            "==================================\n"
            f"Домен: {host}\n"
            f"Порт: {port}\n"
            f"Оценка: {grade}"
            + (f" ({score}/100)\n" if score is not None else "\n")
            + (
                f"Сертификат: осталось {cert_days} дн."
                + (f" (до {cert_not_after})\n" if cert_not_after else "\n")
                if cert_days is not None
                else "Сертификат: нет данных\n"
            )
            + format_diff_block(monitoring_diff)
            + f"Ключевой вывод: {top}\n"
            + (f"\nГлавные замечания:\n{highlights}\n" if highlights else "\n")
            + f"\nПолный отчёт: {report_link}\n"
        )
    else:
        body = (
            "TLS Audit — базовый еженедельный отчёт\n"
            "=====================================\n"
            f"Домен: {host}\n"
            f"Порт: {port}\n"
            f"Оценка: {grade}"
            + (f" ({score}/100)\n" if score is not None else "\n")
            + (
                f"Сертификат: осталось {cert_days} дн."
                + (f" (до {cert_not_after})\n" if cert_not_after else "\n")
                if cert_days is not None
                else "Сертификат: нет данных\n"
            )
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
            subscription_store.mark_sent(subscription_id)
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
    interesting = [event for event in events if event.event_type in {"certificate_expiring", "certificate_expired"}]
    if not interesting:
        return
    subscription_id = optional_int(job.get("subscription_id"))
    email = str(job.get("subscription_email") or "").strip()
    if not subscription_id or not email:
        return
    smtp_url = os.getenv("SMTP_URL", "").strip()
    if not smtp_url:
        return
    deliverable: list[MonitoringEvent] = []
    for event in interesting:
        if subscription_store.should_send_alert(subscription_id, event.event_type, ALERT_COOLDOWN_SECONDS):
            deliverable.append(event)
    if not deliverable:
        return
    host = str(job.get("host") or "")
    grade = str(report.get("grade") or "n/a")
    score = report.get("score")
    subject = f"TLS Audit Pro alert: {host} — {deliverable[0].title}"
    lines = [
        "TLS Audit Pro — alert",
        "=====================",
        f"Домен: {host}",
        f"Оценка: {grade}" + (f" ({score}/100)" if score is not None else ""),
        "",
        "События:",
    ]
    for event in deliverable:
        detail = f": {event.detail}" if event.detail else ""
        lines.append(f"- [{event.severity.upper()}] {event.title}{detail}")
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
            for event in deliverable:
                subscription_store.mark_alert_sent(subscription_id, event.event_type)
    except Exception as exc:  # noqa: BLE001
        log_event(
            logger,
            "subscription_alert_email_failed",
            subscription_id=subscription_id,
            email=email,
            error=str(exc),
        )

def top_findings(report: Dict[str, object], limit: int = 3) -> str:
    items = report.get("findings") or []
    if not isinstance(items, list):
        return ""
    rank = {"critical": 0, "high": 1, "medium": 2, "info": 3}
    normalized = []
    for item in items:
        if not isinstance(item, dict):
            continue
        severity = str(item.get("severity") or "info").lower()
        title = str(item.get("title") or "").strip()
        if not title:
            continue
        normalized.append((rank.get(severity, 9), severity.upper(), title))
    normalized.sort(key=lambda item: item[0])
    if not normalized:
        return ""
    unique = []
    seen = set()
    for item in normalized:
        key = (item[1], item[2])
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    lines = []
    for _, sev, title in unique[: max(1, int(limit))]:
        lines.append(f"- [{sev}] {title}")
    return "\n".join(lines)


def format_diff_block(diff: Optional[MonitoringDiff]) -> str:
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
    if not parts:
        parts.append("без существенных изменений")
    return "Изменения с прошлого скана: " + "; ".join(parts) + ".\n"


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
