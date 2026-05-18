from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from .jobs import JobRecord
from .monitoring_store import MonitoredDomain, NullMonitoringStore
from .traffic_control import TargetScanGuard
from .validation import validate_target


@dataclass
class ScheduledScan:
    domain_id: int
    host: str
    port: int
    job_id: str
    status: str = "queued"


@dataclass
class SchedulerResult:
    queued: List[ScheduledScan] = field(default_factory=list)
    skipped: List[Dict[str, object]] = field(default_factory=list)


def schedule_due_scans(
    monitoring_store: NullMonitoringStore,
    job_store,
    enqueue_scan_job: Callable[[Dict[str, object]], None],
    target_scan_guard: Optional[TargetScanGuard] = None,
    limit: int = 50,
) -> SchedulerResult:
    result = SchedulerResult()
    for domain in monitoring_store.due_domains(limit=limit):
        scheduled = schedule_domain_scan(
            domain,
            monitoring_store,
            job_store,
            enqueue_scan_job,
            target_scan_guard=target_scan_guard,
        )
        if isinstance(scheduled, ScheduledScan):
            result.queued.append(scheduled)
        else:
            result.skipped.append(scheduled)
    return result


def schedule_domain_scan(
    domain: MonitoredDomain,
    monitoring_store: NullMonitoringStore,
    job_store,
    enqueue_scan_job: Callable[[Dict[str, object]], None],
    target_scan_guard: Optional[TargetScanGuard] = None,
):
    try:
        target = validate_target(domain.host, domain.port, resolve=True)
    except ValueError as exc:
        return skip(domain, "validation_failed", str(exc))

    job: JobRecord = job_store.create(target.host, target.port, target.addresses)
    if target_scan_guard:
        decision = target_scan_guard.reserve(target.host, target.port, job.id)
        if not decision.allowed:
            job_store.delete(job.id)
            return skip(
                domain,
                decision.reason or "target_not_available",
                "Домен уже сканируется или находится в cooldown.",
                retry_after=decision.retry_after,
                existing_job_id=decision.job_id,
            )

    payload = {
        "id": job.id,
        "host": job.host,
        "port": job.port,
        "addresses": job.addresses,
        "trigger": "scheduled",
        "monitored_domain_id": domain.id,
    }
    try:
        enqueue_scan_job(payload)
    except Exception as exc:
        job_store.delete(job.id)
        if target_scan_guard:
            target_scan_guard.release(target.host, target.port, job.id, cooldown=False)
        return skip(domain, "enqueue_failed", str(exc))

    monitoring_store.mark_scan_scheduled(domain.id, job.id)
    return ScheduledScan(
        domain_id=domain.id,
        host=job.host,
        port=job.port,
        job_id=job.id,
    )


def skip(
    domain: MonitoredDomain,
    reason: str,
    detail: str = "",
    **extra: object,
) -> Dict[str, object]:
    payload = {
        "domain_id": domain.id,
        "host": domain.host,
        "port": domain.port,
        "reason": reason,
        "detail": detail,
    }
    payload.update(extra)
    return payload
