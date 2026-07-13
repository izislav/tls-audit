import logging
import os
import time
from typing import Callable, Optional

from services.api.app.jobs import job_store
from services.api.app.archive import archive_store
from services.api.app.monitoring import monitoring_store
from services.api.app.queue import enqueue_scan_job
from services.api.app.subscriptions import subscription_store
from services.api.app.target_guard import target_scan_guard
from shared.tls_audit.logging import log_event
from shared.tls_audit.monitoring_scheduler import SchedulerResult, schedule_domain_scan, schedule_due_scans

logger = logging.getLogger("tls_audit.scheduler")


def get_poll_seconds() -> int:
    return positive_int(os.getenv("SCHEDULER_POLL_SECONDS"), default=300)


def get_batch_size() -> int:
    return positive_int(os.getenv("SCHEDULER_BATCH_SIZE"), default=50)


def positive_int(value: Optional[str], default: int) -> int:
    if value is None or value == "":
        return default
    try:
        parsed = int(value)
    except ValueError:
        return default
    if parsed < 1:
        return default
    return parsed


def run_once(limit: Optional[int] = None) -> SchedulerResult:
    batch_size = limit or get_batch_size()
    write_scheduler_heartbeat()
    reconcile_subscription_domains()
    result = schedule_due_scans(
        monitoring_store=monitoring_store,
        job_store=job_store,
        enqueue_scan_job=enqueue_scan_job,
        archive_store=archive_store,
        target_scan_guard=target_scan_guard,
        limit=batch_size,
    )
    log_event(
        logger,
        "monitor_scheduler_tick",
        limit=batch_size,
        queued=len(result.queued),
        skipped=len(result.skipped),
    )
    process_subscriptions(limit=batch_size)
    return result


def write_scheduler_heartbeat() -> None:
    client = getattr(job_store, "client", None)
    if client is not None:
        client.set("tls-audit:scheduler:heartbeat", str(time.time()), ex=1800)


def reconcile_subscription_domains() -> int:
    if not getattr(monitoring_store, "enabled", False):
        return 0
    disabled = 0
    for domain in monitoring_store.list_domains(limit=1000):
        if not str(domain.notes or "").startswith("subscription:"):
            continue
        if subscription_store.active_for_target(domain.host, domain.port):
            continue
        if domain.enabled:
            monitoring_store.update_domain(domain.id, enabled=False)
            disabled += 1
    if disabled:
        log_event(logger, "orphan_subscription_domains_disabled", count=disabled)
    return disabled


def process_subscriptions(limit: int) -> None:
    due = subscription_store.due(limit=max(1, int(limit)))
    if not due:
        return
    for sub in due:
        domain = monitoring_store.upsert_domain(
            host=sub.host,
            port=sub.port,
            enabled=True,
            notes=f"subscription:{sub.email}",
        )
        scheduled = schedule_domain_scan(
            domain=domain,
            monitoring_store=monitoring_store,
            job_store=job_store,
            enqueue_scan_job=enqueue_scan_job,
            archive_store=archive_store,
            target_scan_guard=target_scan_guard,
            payload_extra={
                "subscription_id": sub.id,
                "subscription_email": sub.email,
                "subscription_plan": sub.plan,
            },
        )
        if isinstance(scheduled, dict):
            log_event(
                logger,
                "subscription_scan_skipped",
                subscription_id=sub.id,
                email=sub.email,
                host=sub.host,
                reason=scheduled.get("reason"),
            )
            continue
        log_event(
            logger,
            "subscription_scan_queued",
            subscription_id=sub.id,
            email=sub.email,
            host=sub.host,
            port=sub.port,
            job_id=scheduled.job_id,
        )


def run_subscription_now(subscription_id: int) -> dict:
    sub = subscription_store.get_by_id(int(subscription_id))
    if not sub:
        return {"status": "not_found"}
    if not sub.enabled:
        return {"status": "disabled"}
    if not sub.confirmed:
        return {"status": "not_confirmed"}
    domain = monitoring_store.upsert_domain(
        host=sub.host,
        port=sub.port,
        enabled=True,
        notes=f"subscription:{sub.email}",
    )
    scheduled = schedule_domain_scan(
        domain=domain,
        monitoring_store=monitoring_store,
        job_store=job_store,
        enqueue_scan_job=enqueue_scan_job,
        archive_store=archive_store,
        target_scan_guard=target_scan_guard,
        payload_extra={
            "subscription_id": sub.id,
            "subscription_email": sub.email,
            "subscription_plan": sub.plan,
        },
    )
    if isinstance(scheduled, dict):
        return {"status": "skipped", **scheduled}
    return {"status": "queued", "job_id": scheduled.job_id, "host": sub.host, "port": sub.port}

def run_loop(
    poll_seconds: Optional[int] = None,
    limit: Optional[int] = None,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    interval = poll_seconds or get_poll_seconds()
    batch_size = limit or get_batch_size()
    log_event(
        logger,
        "monitor_scheduler_started",
        poll_seconds=interval,
        limit=batch_size,
    )
    while True:
        try:
            run_once(limit=batch_size)
        except Exception as exc:
            log_event(
                logger,
                "monitor_scheduler_failed",
                error=str(exc),
                error_type=exc.__class__.__name__,
            )
        sleep(interval)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    run_loop()


if __name__ == "__main__":
    main()
