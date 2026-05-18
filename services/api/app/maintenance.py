import argparse
import json

from .archive import archive_store
from .jobs import job_store
from .monitoring import monitoring_store
from .queue import enqueue_scan_job
from .settings import settings
from .target_guard import target_scan_guard
from shared.tls_audit.monitoring_scheduler import schedule_due_scans


def cleanup_reports(retention_days: int, error_retention_days: int) -> dict[str, int]:
    if not archive_store.enabled:
        return {"deleted_done": 0, "deleted_error": 0}
    return archive_store.cleanup(
        retention_days=retention_days,
        error_retention_days=error_retention_days,
    )


def report_stats(days: int) -> dict[str, object]:
    return archive_store.stats(days=days)


def add_monitored_domain(
    host: str,
    port: int,
    interval_seconds: int,
    enabled: bool,
    notes: str,
) -> dict[str, object]:
    domain = monitoring_store.upsert_domain(
        host=host,
        port=port,
        scan_interval_seconds=interval_seconds,
        enabled=enabled,
        notes=notes,
    )
    return domain.__dict__


def due_monitored_domains(limit: int) -> list[dict[str, object]]:
    return [domain.__dict__ for domain in monitoring_store.due_domains(limit=limit)]


def schedule_monitored_domains(limit: int) -> dict[str, object]:
    result = schedule_due_scans(
        monitoring_store=monitoring_store,
        job_store=job_store,
        enqueue_scan_job=enqueue_scan_job,
        target_scan_guard=target_scan_guard,
        limit=limit,
    )
    return {
        "queued": [item.__dict__ for item in result.queued],
        "skipped": result.skipped,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="TLS Audit maintenance commands.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    cleanup = subparsers.add_parser("cleanup", help="Delete old archived scans.")
    cleanup.add_argument(
        "--retention-days",
        type=int,
        default=settings.report_retention_days,
        help="How long to keep successful reports.",
    )
    cleanup.add_argument(
        "--error-retention-days",
        type=int,
        default=settings.error_retention_days,
        help="How long to keep failed scan rows.",
    )
    stats = subparsers.add_parser("stats", help="Print privacy-friendly scan statistics.")
    stats.add_argument(
        "--days",
        type=int,
        default=7,
        help="Number of recent days to include.",
    )
    monitor_add = subparsers.add_parser("monitor-add", help="Add or update monitored domain.")
    monitor_add.add_argument("host", help="Public hostname to monitor.")
    monitor_add.add_argument("--port", type=int, default=443)
    monitor_add.add_argument("--interval-seconds", type=int, default=86400)
    monitor_add.add_argument("--disabled", action="store_true")
    monitor_add.add_argument("--notes", default="")

    monitor_due = subparsers.add_parser("monitor-due", help="List monitored domains due for scan.")
    monitor_due.add_argument("--limit", type=int, default=50)

    monitor_schedule = subparsers.add_parser(
        "monitor-schedule",
        help="Enqueue due monitored domains for scanning.",
    )
    monitor_schedule.add_argument("--limit", type=int, default=50)

    args = parser.parse_args()
    if args.command == "cleanup":
        result = cleanup_reports(args.retention_days, args.error_retention_days)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    elif args.command == "stats":
        result = report_stats(args.days)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, default=str))
    elif args.command == "monitor-add":
        result = add_monitored_domain(
            host=args.host,
            port=args.port,
            interval_seconds=args.interval_seconds,
            enabled=not args.disabled,
            notes=args.notes,
        )
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, default=str))
    elif args.command == "monitor-due":
        result = due_monitored_domains(limit=args.limit)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, default=str))
    elif args.command == "monitor-schedule":
        result = schedule_monitored_domains(limit=args.limit)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, default=str))


if __name__ == "__main__":
    main()
