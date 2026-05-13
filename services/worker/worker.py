import json
import logging
import os
import time
from typing import Dict, Optional

from shared.tls_audit.adapter import run_full_scan
from shared.tls_audit.archive import create_archive_store
from shared.tls_audit.jobs import create_job_store
from shared.tls_audit.logging import log_event
from shared.tls_audit.traffic_control import TargetScanGuard
from shared.tls_audit.validation import validate_worker_target


QUEUE_FILE = os.getenv("DEV_QUEUE_FILE", "/tmp/tls-audit-jobs.jsonl")
QUEUE_NAME = os.getenv("SCAN_QUEUE_NAME", "tls-audit:scan-jobs")
REDIS_URL = os.getenv("REDIS_URL", "")
DATABASE_URL = os.getenv("DATABASE_URL", "")
POLL_SECONDS = float(os.getenv("WORKER_POLL_SECONDS", "1.0"))
TARGET_COOLDOWN_SECONDS = int(os.getenv("TARGET_COOLDOWN_SECONDS", "30"))
ACTIVE_SCAN_TTL_SECONDS = int(os.getenv("ACTIVE_SCAN_TTL_SECONDS", "900"))
job_store = create_job_store(REDIS_URL)
archive_store = create_archive_store(DATABASE_URL)
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
    result = mark_done(job_id, report.to_dict())
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
