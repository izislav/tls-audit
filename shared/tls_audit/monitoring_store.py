from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from .monitoring import FindingSummary, MonitoringEvent, MonitoringSnapshot

DEFAULT_SCAN_INTERVAL_SECONDS = 86400
MIN_SCAN_INTERVAL_SECONDS = 86400


@dataclass
class MonitoredDomain:
    id: int
    host: str
    port: int = 443
    enabled: bool = True
    scan_interval_seconds: int = DEFAULT_SCAN_INTERVAL_SECONDS
    last_scan_at: Optional[datetime] = None
    next_scan_at: Optional[datetime] = None
    notes: str = ""


class NullMonitoringStore:
    enabled = False

    def upsert_domain(
        self,
        host: str,
        port: int = 443,
        scan_interval_seconds: int = DEFAULT_SCAN_INTERVAL_SECONDS,
        enabled: bool = True,
        notes: str = "",
    ) -> MonitoredDomain:
        return MonitoredDomain(
            id=0,
            host=host,
            port=port,
            enabled=enabled,
            scan_interval_seconds=normalize_scan_interval(scan_interval_seconds),
            notes=notes,
        )

    def due_domains(self, limit: int = 50, now: Optional[datetime] = None) -> List[MonitoredDomain]:
        return []

    def list_domains(self, limit: int = 100) -> List[MonitoredDomain]:
        return []

    def mark_scan_scheduled(
        self,
        domain_id: int,
        scan_id: str,
        now: Optional[datetime] = None,
    ) -> None:
        return

    def save_snapshot(self, snapshot: MonitoringSnapshot) -> MonitoringSnapshot:
        return snapshot

    def latest_snapshot(
        self,
        monitored_domain_id: int,
        before_snapshot_id: Optional[int] = None,
    ) -> Optional[MonitoringSnapshot]:
        return None

    def save_events(
        self,
        monitored_domain_id: int,
        snapshot_id: Optional[int],
        scan_id: Optional[str],
        events: List[MonitoringEvent],
    ) -> None:
        return

    def list_snapshots(self, monitored_domain_id: int, limit: int = 20) -> List[MonitoringSnapshot]:
        return []

    def list_events(self, monitored_domain_id: int, limit: int = 50) -> List[Dict[str, object]]:
        return []


class InMemoryMonitoringStore(NullMonitoringStore):
    enabled = True

    def __init__(self) -> None:
        self.domains: Dict[int, MonitoredDomain] = {}
        self.snapshots: Dict[int, MonitoringSnapshot] = {}
        self.events: List[Dict[str, object]] = []
        self._domain_id = 0
        self._snapshot_id = 0

    def upsert_domain(
        self,
        host: str,
        port: int = 443,
        scan_interval_seconds: int = DEFAULT_SCAN_INTERVAL_SECONDS,
        enabled: bool = True,
        notes: str = "",
    ) -> MonitoredDomain:
        now = utcnow()
        scan_interval_seconds = normalize_scan_interval(scan_interval_seconds)
        for domain in self.domains.values():
            if domain.host == host and domain.port == port:
                domain.enabled = enabled
                domain.scan_interval_seconds = scan_interval_seconds
                domain.notes = notes
                if domain.next_scan_at is None:
                    domain.next_scan_at = now
                return domain

        self._domain_id += 1
        domain = MonitoredDomain(
            id=self._domain_id,
            host=host,
            port=port,
            enabled=enabled,
            scan_interval_seconds=scan_interval_seconds,
            next_scan_at=now,
            notes=notes,
        )
        self.domains[domain.id] = domain
        return domain

    def due_domains(self, limit: int = 50, now: Optional[datetime] = None) -> List[MonitoredDomain]:
        now = now or utcnow()
        due = [
            domain
            for domain in self.domains.values()
            if domain.enabled and (domain.next_scan_at is None or domain.next_scan_at <= now)
        ]
        return sorted(due, key=lambda item: item.next_scan_at or now)[: max(1, limit)]

    def list_domains(self, limit: int = 100) -> List[MonitoredDomain]:
        items = sorted(
            self.domains.values(),
            key=lambda item: (item.next_scan_at or utcnow(), item.id),
        )
        return items[: max(1, limit)]

    def mark_scan_scheduled(
        self,
        domain_id: int,
        scan_id: str,
        now: Optional[datetime] = None,
    ) -> None:
        now = now or utcnow()
        domain = self.domains[domain_id]
        domain.last_scan_at = now
        domain.next_scan_at = now + timedelta(seconds=domain.scan_interval_seconds)

    def save_snapshot(self, snapshot: MonitoringSnapshot) -> MonitoringSnapshot:
        self._snapshot_id += 1
        snapshot.id = self._snapshot_id
        snapshot.created_at = snapshot.created_at or utcnow()
        self.snapshots[snapshot.id] = snapshot
        return snapshot

    def latest_snapshot(
        self,
        monitored_domain_id: int,
        before_snapshot_id: Optional[int] = None,
    ) -> Optional[MonitoringSnapshot]:
        items = [
            snapshot
            for snapshot in self.snapshots.values()
            if snapshot.monitored_domain_id == monitored_domain_id
            and (before_snapshot_id is None or (snapshot.id or 0) < before_snapshot_id)
        ]
        if not items:
            return None
        return sorted(items, key=lambda item: item.id or 0, reverse=True)[0]

    def save_events(
        self,
        monitored_domain_id: int,
        snapshot_id: Optional[int],
        scan_id: Optional[str],
        events: List[MonitoringEvent],
    ) -> None:
        for event in events:
            self.events.append(
                {
                    "monitored_domain_id": monitored_domain_id,
                    "snapshot_id": snapshot_id,
                    "scan_id": scan_id,
                    "event_type": event.event_type,
                    "severity": event.severity,
                    "title": event.title,
                    "detail": event.detail,
                    "payload": event.payload,
                }
            )

    def list_snapshots(self, monitored_domain_id: int, limit: int = 20) -> List[MonitoringSnapshot]:
        items = [
            snapshot
            for snapshot in self.snapshots.values()
            if snapshot.monitored_domain_id == monitored_domain_id
        ]
        return sorted(items, key=lambda item: item.id or 0, reverse=True)[: max(1, limit)]

    def list_events(self, monitored_domain_id: int, limit: int = 50) -> List[Dict[str, object]]:
        items = [
            event for event in self.events if event["monitored_domain_id"] == monitored_domain_id
        ]
        return list(reversed(items))[: max(1, limit)]


class PostgresMonitoringStore(NullMonitoringStore):
    enabled = True

    def __init__(self, database_url: str) -> None:
        self.database_url = database_url

    def upsert_domain(
        self,
        host: str,
        port: int = 443,
        scan_interval_seconds: int = DEFAULT_SCAN_INTERVAL_SECONDS,
        enabled: bool = True,
        notes: str = "",
    ) -> MonitoredDomain:
        scan_interval_seconds = normalize_scan_interval(scan_interval_seconds)
        with self.connect() as conn:
            row = conn.execute(
                """
                INSERT INTO monitored_domains (
                    host, port, enabled, scan_interval_seconds, notes
                )
                VALUES (%(host)s, %(port)s, %(enabled)s, %(scan_interval_seconds)s, %(notes)s)
                ON CONFLICT (host, port) DO UPDATE SET
                    enabled = EXCLUDED.enabled,
                    scan_interval_seconds = EXCLUDED.scan_interval_seconds,
                    notes = EXCLUDED.notes
                RETURNING id, host, port, enabled, scan_interval_seconds,
                          last_scan_at, next_scan_at, notes
                """,
                {
                    "host": host,
                    "port": int(port),
                    "enabled": bool(enabled),
                    "scan_interval_seconds": int(scan_interval_seconds),
                    "notes": notes,
                },
            ).fetchone()
        return domain_from_row(row)

    def due_domains(self, limit: int = 50, now: Optional[datetime] = None) -> List[MonitoredDomain]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT id, host, port, enabled, scan_interval_seconds,
                       last_scan_at, next_scan_at, notes
                FROM monitored_domains
                WHERE enabled = true
                  AND next_scan_at <= coalesce(%s, now())
                ORDER BY next_scan_at ASC
                LIMIT %s
                """,
                (now, max(1, int(limit))),
            ).fetchall()
        return [domain_from_row(row) for row in rows]

    def list_domains(self, limit: int = 100) -> List[MonitoredDomain]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT id, host, port, enabled, scan_interval_seconds,
                       last_scan_at, next_scan_at, notes
                FROM monitored_domains
                ORDER BY enabled DESC, next_scan_at ASC, id ASC
                LIMIT %s
                """,
                (max(1, int(limit)),),
            ).fetchall()
        return [domain_from_row(row) for row in rows]

    def mark_scan_scheduled(
        self,
        domain_id: int,
        scan_id: str,
        now: Optional[datetime] = None,
    ) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE monitored_domains
                SET last_scan_at = coalesce(%(now)s, now()),
                    next_scan_at = coalesce(%(now)s, now())
                        + (scan_interval_seconds * interval '1 second')
                WHERE id = %(id)s
                """,
                {"id": int(domain_id), "now": now, "scan_id": scan_id},
            )

    def save_snapshot(self, snapshot: MonitoringSnapshot) -> MonitoringSnapshot:
        from psycopg.types.json import Jsonb

        with self.connect() as conn:
            row = conn.execute(
                """
                INSERT INTO monitoring_snapshots (
                    monitored_domain_id, scan_id, grade, score,
                    certificate_not_after, certificate_expires_in_days,
                    supported_protocols, hsts, findings
                )
                VALUES (
                    %(monitored_domain_id)s, %(scan_id)s, %(grade)s, %(score)s,
                    %(certificate_not_after)s, %(certificate_expires_in_days)s,
                    %(supported_protocols)s, %(hsts)s, %(findings)s
                )
                ON CONFLICT (monitored_domain_id, scan_id) DO UPDATE SET
                    grade = EXCLUDED.grade,
                    score = EXCLUDED.score,
                    certificate_not_after = EXCLUDED.certificate_not_after,
                    certificate_expires_in_days = EXCLUDED.certificate_expires_in_days,
                    supported_protocols = EXCLUDED.supported_protocols,
                    hsts = EXCLUDED.hsts,
                    findings = EXCLUDED.findings
                RETURNING id, created_at
                """,
                {
                    "monitored_domain_id": snapshot.monitored_domain_id,
                    "scan_id": snapshot.scan_id,
                    "grade": snapshot.grade,
                    "score": snapshot.score,
                    "certificate_not_after": snapshot.certificate_not_after,
                    "certificate_expires_in_days": snapshot.certificate_expires_in_days,
                    "supported_protocols": Jsonb(snapshot.supported_protocols),
                    "hsts": Jsonb(snapshot.hsts),
                    "findings": Jsonb([finding.to_dict() for finding in snapshot.findings]),
                },
            ).fetchone()
        snapshot.id = int(row["id"])
        snapshot.created_at = row["created_at"]
        return snapshot

    def latest_snapshot(
        self,
        monitored_domain_id: int,
        before_snapshot_id: Optional[int] = None,
    ) -> Optional[MonitoringSnapshot]:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT id, monitored_domain_id, scan_id, grade, score,
                       certificate_not_after, certificate_expires_in_days,
                       supported_protocols, hsts, findings, created_at
                FROM monitoring_snapshots
                WHERE monitored_domain_id = %(monitored_domain_id)s
                  AND (%(before_snapshot_id)s IS NULL OR id < %(before_snapshot_id)s)
                ORDER BY id DESC
                LIMIT 1
                """,
                {
                    "monitored_domain_id": int(monitored_domain_id),
                    "before_snapshot_id": before_snapshot_id,
                },
            ).fetchone()
        return snapshot_from_row(row) if row else None

    def list_snapshots(self, monitored_domain_id: int, limit: int = 20) -> List[MonitoringSnapshot]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT id, monitored_domain_id, scan_id, grade, score,
                       certificate_not_after, certificate_expires_in_days,
                       supported_protocols, hsts, findings, created_at
                FROM monitoring_snapshots
                WHERE monitored_domain_id = %s
                ORDER BY id DESC
                LIMIT %s
                """,
                (int(monitored_domain_id), max(1, int(limit))),
            ).fetchall()
        return [snapshot_from_row(row) for row in rows]

    def save_events(
        self,
        monitored_domain_id: int,
        snapshot_id: Optional[int],
        scan_id: Optional[str],
        events: List[MonitoringEvent],
    ) -> None:
        from psycopg.types.json import Jsonb

        with self.connect() as conn:
            for event in events:
                conn.execute(
                    """
                    INSERT INTO monitoring_events (
                        monitored_domain_id, snapshot_id, scan_id, event_type,
                        severity, title, detail, payload
                    )
                    VALUES (
                        %(monitored_domain_id)s, %(snapshot_id)s, %(scan_id)s,
                        %(event_type)s, %(severity)s, %(title)s, %(detail)s,
                        %(payload)s
                    )
                    """,
                    {
                        "monitored_domain_id": int(monitored_domain_id),
                        "snapshot_id": snapshot_id,
                        "scan_id": scan_id,
                        "event_type": event.event_type,
                        "severity": event.severity,
                        "title": event.title,
                        "detail": event.detail,
                        "payload": Jsonb(event.payload),
                    },
                )

    def list_events(self, monitored_domain_id: int, limit: int = 50) -> List[Dict[str, object]]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT id, monitored_domain_id, snapshot_id, scan_id, event_type,
                       severity, title, detail, payload, created_at
                FROM monitoring_events
                WHERE monitored_domain_id = %s
                ORDER BY id DESC
                LIMIT %s
                """,
                (int(monitored_domain_id), max(1, int(limit))),
            ).fetchall()
        return [event_from_row(row) for row in rows]

    def connect(self):
        import psycopg
        from psycopg.rows import dict_row

        return psycopg.connect(self.database_url, row_factory=dict_row)


def create_monitoring_store(database_url: str = ""):
    if database_url:
        return PostgresMonitoringStore(database_url)
    return NullMonitoringStore()


def domain_from_row(row: Dict[str, object]) -> MonitoredDomain:
    return MonitoredDomain(
        id=int(row["id"]),
        host=str(row["host"]),
        port=int(row["port"]),
        enabled=bool(row["enabled"]),
        scan_interval_seconds=int(row["scan_interval_seconds"]),
        last_scan_at=row.get("last_scan_at"),
        next_scan_at=row.get("next_scan_at"),
        notes=str(row.get("notes") or ""),
    )


def normalize_scan_interval(scan_interval_seconds: int) -> int:
    return max(MIN_SCAN_INTERVAL_SECONDS, int(scan_interval_seconds))


def snapshot_from_row(row: Dict[str, object]) -> MonitoringSnapshot:
    return MonitoringSnapshot(
        id=int(row["id"]),
        monitored_domain_id=int(row["monitored_domain_id"]),
        scan_id=str(row["scan_id"]),
        grade=row.get("grade"),
        score=row.get("score"),
        certificate_not_after=(
            row["certificate_not_after"].isoformat()
            if row.get("certificate_not_after") is not None
            else None
        ),
        certificate_expires_in_days=row.get("certificate_expires_in_days"),
        supported_protocols=list(row.get("supported_protocols") or []),
        hsts=dict(row.get("hsts") or {}),
        findings=[
            FindingSummary(
                code=str(item.get("code") or "unknown"),
                title=str(item.get("title") or item.get("code") or "Finding"),
                severity=str(item.get("severity") or "info"),
                category=str(item.get("category") or "general"),
            )
            for item in list(row.get("findings") or [])
        ],
        created_at=row.get("created_at"),
    )


def event_from_row(row: Dict[str, object]) -> Dict[str, object]:
    return {
        "id": int(row["id"]),
        "monitored_domain_id": int(row["monitored_domain_id"]),
        "snapshot_id": row.get("snapshot_id"),
        "scan_id": row.get("scan_id"),
        "event_type": str(row["event_type"]),
        "severity": str(row["severity"]),
        "title": str(row["title"]),
        "detail": str(row.get("detail") or ""),
        "payload": dict(row.get("payload") or {}),
        "created_at": row.get("created_at"),
    }


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
