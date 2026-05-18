import logging
import os
import time
from typing import Callable, Optional

from services.api.app.jobs import job_store
from services.api.app.monitoring import monitoring_store
from services.api.app.queue import enqueue_scan_job
from services.api.app.target_guard import target_scan_guard
from shared.tls_audit.logging import log_event
from shared.tls_audit.monitoring_scheduler import SchedulerResult, schedule_due_scans

logger = logging.getLogger("tls_audit.scheduler")


def get_poll_seconds() -> int:
    return positive_int(os.getenv("SCHEDULER_POLL_SECONDS"), default=60)


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
    result = schedule_due_scans(
        monitoring_store=monitoring_store,
        job_store=job_store,
        enqueue_scan_job=enqueue_scan_job,
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
    return result


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
