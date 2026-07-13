from dataclasses import asdict
from pathlib import Path
from typing import Dict, Optional

from .jobs import JobRecord


SCHEMA_PATH = Path("deploy/postgres/schema.sql")


class NullArchiveStore:
    enabled = False

    def initialize(self) -> None:
        return

    def create_scan(self, job: JobRecord) -> None:
        return

    def update_scan(self, job: JobRecord) -> None:
        return

    def save_report(self, job: JobRecord) -> None:
        return

    def get_report(self, scan_id: str) -> Optional[Dict[str, object]]:
        return None

    def get_scan(self, scan_id: str) -> Optional[Dict[str, object]]:
        return None

    def get_previous_report(self, scan_id: str) -> Optional[Dict[str, object]]:
        return None

    def cleanup(self, retention_days: int = 30, error_retention_days: int = 7) -> Dict[str, int]:
        return {"deleted_done": 0, "deleted_error": 0}

    def stats(self, days: int = 7) -> Dict[str, object]:
        return {
            "enabled": False,
            "days": max(1, int(days)),
            "total_scans": 0,
            "status_counts": {},
            "grade_counts": {},
            "top_findings": [],
        }

    def lifetime_scan_count(self) -> int:
        return 0


class PostgresArchiveStore:
    enabled = True

    def __init__(self, database_url: str) -> None:
        self.database_url = database_url

    def initialize(self) -> None:
        schema = SCHEMA_PATH.read_text(encoding="utf-8")
        with self.connect() as conn:
            conn.execute(schema)

    def create_scan(self, job: JobRecord) -> None:
        with self.connect() as conn:
            existing = conn.execute(
                "SELECT 1 FROM scans WHERE id = %s",
                (job.id,),
            ).fetchone()
            conn.execute(
                """
                INSERT INTO scans (
                    id, host, port, addresses, status, progress_percent,
                    progress_stage, progress_detail, error
                )
                VALUES (
                    %(id)s, %(host)s, %(port)s, %(addresses)s, %(status)s,
                    %(progress_percent)s, %(progress_stage)s,
                    %(progress_detail)s, %(error)s
                )
                ON CONFLICT (id) DO UPDATE SET
                    host = EXCLUDED.host,
                    port = EXCLUDED.port,
                    addresses = EXCLUDED.addresses,
                    status = EXCLUDED.status,
                    progress_percent = EXCLUDED.progress_percent,
                    progress_stage = EXCLUDED.progress_stage,
                    progress_detail = EXCLUDED.progress_detail,
                    error = EXCLUDED.error
                """,
                self.scan_payload(job),
            )
            if not existing:
                conn.execute(
                    """
                    INSERT INTO site_counters (name, value)
                    VALUES ('scans_total', 1)
                    ON CONFLICT (name) DO UPDATE
                    SET value = site_counters.value + 1
                    """
                )

    def update_scan(self, job: JobRecord) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE scans
                SET status = %(status)s,
                    progress_percent = %(progress_percent)s,
                    progress_stage = %(progress_stage)s,
                    progress_detail = %(progress_detail)s,
                    error = %(error)s,
                    grade = %(grade)s,
                    score = %(score)s,
                    started_at = CASE
                        WHEN %(status)s = 'running' AND started_at IS NULL THEN now()
                        ELSE started_at
                    END,
                    finished_at = CASE
                        WHEN %(status)s IN ('done', 'error') THEN now()
                        ELSE finished_at
                    END
                WHERE id = %(id)s
                """,
                self.scan_payload(job),
            )

    def save_report(self, job: JobRecord) -> None:
        if not job.report:
            self.update_scan(job)
            return

        with self.connect() as conn:
            payload = self.scan_payload(job)
            conn.execute(
                """
                UPDATE scans
                SET status = %(status)s,
                    progress_percent = %(progress_percent)s,
                    progress_stage = %(progress_stage)s,
                    progress_detail = %(progress_detail)s,
                    error = %(error)s,
                    grade = %(grade)s,
                    score = %(score)s,
                    finished_at = CASE
                        WHEN %(status)s IN ('done', 'error') THEN now()
                        ELSE finished_at
                    END
                WHERE id = %(id)s
                """,
                payload,
            )
            conn.execute(
                """
                INSERT INTO reports (scan_id, report, raw)
                VALUES (%(id)s, %(report)s, %(raw)s)
                ON CONFLICT (scan_id) DO UPDATE SET
                    report = EXCLUDED.report,
                    raw = EXCLUDED.raw,
                    created_at = now()
                """,
                payload,
            )
            conn.execute("DELETE FROM findings WHERE scan_id = %(id)s", payload)
            for finding in job.report.get("findings") or []:
                conn.execute(
                    """
                    INSERT INTO findings (
                        scan_id, severity, code, category, title, detail,
                        grade_cap, score_penalty, recommendation, evidence
                    )
                    VALUES (
                        %(scan_id)s, %(severity)s, %(code)s, %(category)s,
                        %(title)s, %(detail)s, %(grade_cap)s,
                        %(score_penalty)s, %(recommendation)s, %(evidence)s
                    )
                    """,
                    self.finding_payload(job.id, finding),
                )

    def get_report(self, scan_id: str) -> Optional[Dict[str, object]]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT report FROM reports WHERE scan_id = %s",
                (scan_id,),
            ).fetchone()
        return row["report"] if row else None

    def get_scan(self, scan_id: str) -> Optional[Dict[str, object]]:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT id, host, port, addresses, status, progress_percent,
                       progress_stage, progress_detail, error, grade, score,
                       created_at, updated_at, started_at, finished_at
                FROM scans
                WHERE id = %s
                """,
                (scan_id,),
            ).fetchone()
        return dict(row) if row else None

    def get_previous_report(self, scan_id: str) -> Optional[Dict[str, object]]:
        with self.connect() as conn:
            current = conn.execute(
                """
                SELECT id, host, port, created_at
                FROM scans
                WHERE id = %s
                """,
                (scan_id,),
            ).fetchone()
            if not current:
                return None

            row = conn.execute(
                """
                SELECT s.id, s.host, s.port, s.grade, s.score,
                       s.created_at, s.started_at, s.finished_at, r.report
                FROM scans s
                JOIN reports r ON r.scan_id = s.id
                WHERE s.host = %(host)s
                  AND s.port = %(port)s
                  AND s.status = 'done'
                  AND s.id <> %(id)s
                  AND s.created_at < %(created_at)s
                ORDER BY s.created_at DESC
                LIMIT 1
                """,
                {
                    "id": current["id"],
                    "host": current["host"],
                    "port": current["port"],
                    "created_at": current["created_at"],
                },
            ).fetchone()
        if not row:
            return None
        data = dict(row)
        data["scan"] = {
            "id": data.pop("id"),
            "host": data.pop("host"),
            "port": data.pop("port"),
            "grade": data.pop("grade"),
            "score": data.pop("score"),
            "created_at": data.pop("created_at"),
            "started_at": data.pop("started_at"),
            "finished_at": data.pop("finished_at"),
        }
        return data

    def cleanup(self, retention_days: int = 30, error_retention_days: int = 7) -> Dict[str, int]:
        retention_days = max(1, int(retention_days))
        error_retention_days = max(1, int(error_retention_days))
        with self.connect() as conn:
            deleted_done = conn.execute(
                """
                WITH deleted AS (
                    DELETE FROM scans
                    WHERE status = 'done'
                      AND created_at < now() - (%s * interval '1 day')
                      AND NOT EXISTS (
                          SELECT 1
                          FROM monitoring_snapshots ms
                          WHERE ms.scan_id = scans.id
                      )
                    RETURNING id
                )
                SELECT count(*) AS count FROM deleted
                """,
                (retention_days,),
            ).fetchone()
            deleted_error = conn.execute(
                """
                WITH deleted AS (
                    DELETE FROM scans
                    WHERE status = 'error'
                      AND created_at < now() - (%s * interval '1 day')
                    RETURNING id
                )
                SELECT count(*) AS count FROM deleted
                """,
                (error_retention_days,),
            ).fetchone()
        return {
            "deleted_done": int(deleted_done["count"] if deleted_done else 0),
            "deleted_error": int(deleted_error["count"] if deleted_error else 0),
        }

    def stats(self, days: int = 7) -> Dict[str, object]:
        days = max(1, int(days))
        with self.connect() as conn:
            summary = conn.execute(
                """
                SELECT
                    count(*) AS total_scans,
                    count(*) FILTER (WHERE status = 'done') AS done_scans,
                    count(*) FILTER (WHERE status = 'error') AS error_scans,
                    count(DISTINCT host) AS unique_hosts,
                    coalesce(round(avg(score) FILTER (WHERE score IS NOT NULL), 1), 0) AS avg_score,
                    coalesce(round(avg(extract(epoch FROM (finished_at - started_at)))
                        FILTER (WHERE started_at IS NOT NULL AND finished_at IS NOT NULL), 1), 0) AS avg_duration_seconds
                FROM scans
                WHERE created_at >= now() - (%s * interval '1 day')
                """,
                (days,),
            ).fetchone()
            status_rows = conn.execute(
                """
                SELECT status, count(*) AS count
                FROM scans
                WHERE created_at >= now() - (%s * interval '1 day')
                GROUP BY status
                ORDER BY count DESC, status
                """,
                (days,),
            ).fetchall()
            grade_rows = conn.execute(
                """
                SELECT coalesce(grade, 'unknown') AS grade, count(*) AS count
                FROM scans
                WHERE created_at >= now() - (%s * interval '1 day')
                GROUP BY coalesce(grade, 'unknown')
                ORDER BY count DESC, grade
                """,
                (days,),
            ).fetchall()
            finding_rows = conn.execute(
                """
                SELECT f.code, f.title, f.severity, count(*) AS count
                FROM findings f
                JOIN scans s ON s.id = f.scan_id
                WHERE s.created_at >= now() - (%s * interval '1 day')
                GROUP BY f.code, f.title, f.severity
                ORDER BY count DESC, f.severity, f.code
                LIMIT 10
                """,
                (days,),
            ).fetchall()
            slow_rows = conn.execute(
                """
                SELECT host, port, status,
                       round(extract(epoch FROM (finished_at - started_at)), 1) AS duration_seconds,
                       grade, score, created_at
                FROM scans
                WHERE created_at >= now() - (%s * interval '1 day')
                  AND started_at IS NOT NULL
                  AND finished_at IS NOT NULL
                ORDER BY finished_at - started_at DESC
                LIMIT 10
                """,
                (days,),
            ).fetchall()
        return {
            "enabled": True,
            "days": days,
            "total_scans": int(summary["total_scans"] or 0),
            "done_scans": int(summary["done_scans"] or 0),
            "error_scans": int(summary["error_scans"] or 0),
            "unique_hosts": int(summary["unique_hosts"] or 0),
            "avg_score": float(summary["avg_score"] or 0),
            "avg_duration_seconds": float(summary["avg_duration_seconds"] or 0),
            "status_counts": {row["status"]: int(row["count"]) for row in status_rows},
            "grade_counts": {row["grade"]: int(row["count"]) for row in grade_rows},
            "top_findings": [dict(row) for row in finding_rows],
            "slowest_scans": [dict(row) for row in slow_rows],
        }

    def lifetime_scan_count(self) -> int:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT value FROM site_counters WHERE name = 'scans_total'"
            ).fetchone()
            if row:
                return int(row["value"] or 0)
            fallback = conn.execute("SELECT count(*) AS count FROM scans").fetchone()
        return int(fallback["count"] or 0) if fallback else 0

    def connect(self):
        import psycopg
        from psycopg.rows import dict_row

        return psycopg.connect(self.database_url, row_factory=dict_row)

    def scan_payload(self, job: JobRecord) -> Dict[str, object]:
        from psycopg.types.json import Jsonb

        report = job.report or {}
        return {
            "id": job.id,
            "host": job.host,
            "port": job.port,
            "addresses": Jsonb(job.addresses),
            "status": job.status,
            "progress_percent": job.progress_percent,
            "progress_stage": job.progress_stage,
            "progress_detail": job.progress_detail,
            "error": job.error,
            "grade": report.get("grade"),
            "score": report.get("score"),
            "report": Jsonb(report),
            "raw": Jsonb(report.get("raw") or {}),
        }

    def finding_payload(self, scan_id: str, finding: Dict[str, object]) -> Dict[str, object]:
        from psycopg.types.json import Jsonb

        return {
            "scan_id": scan_id,
            "severity": finding.get("severity") or "info",
            "code": finding.get("code") or "unknown",
            "category": finding.get("category") or "general",
            "title": finding.get("title") or "",
            "detail": finding.get("detail") or "",
            "grade_cap": finding.get("grade_cap"),
            "score_penalty": finding.get("score_penalty") or 0,
            "recommendation": Jsonb(finding.get("recommendation") or {}),
            "evidence": Jsonb(finding.get("evidence") or {}),
        }


def create_archive_store(database_url: str = ""):
    if database_url:
        return PostgresArchiveStore(database_url)
    return NullArchiveStore()


def job_to_archive_dict(job: JobRecord) -> Dict[str, object]:
    return asdict(job)
