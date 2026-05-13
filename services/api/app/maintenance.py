import argparse
import json

from .archive import archive_store
from .settings import settings


def cleanup_reports(retention_days: int, error_retention_days: int) -> dict[str, int]:
    if not archive_store.enabled:
        return {"deleted_done": 0, "deleted_error": 0}
    return archive_store.cleanup(
        retention_days=retention_days,
        error_retention_days=error_retention_days,
    )


def report_stats(days: int) -> dict[str, object]:
    return archive_store.stats(days=days)


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

    args = parser.parse_args()
    if args.command == "cleanup":
        result = cleanup_reports(args.retention_days, args.error_retention_days)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    elif args.command == "stats":
        result = report_stats(args.days)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, default=str))


if __name__ == "__main__":
    main()
