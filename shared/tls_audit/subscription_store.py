from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
from uuid import uuid4


DEFAULT_WEEKLY_INTERVAL_SECONDS = 7 * 24 * 60 * 60


@dataclass
class MonitorSubscription:
    id: int
    host: str
    port: int
    email: str
    token: str
    plan: str = "free"
    ownership_method: str = ""
    ownership_token: str = ""
    ownership_verified_at: Optional[datetime] = None
    enabled: bool = True
    confirmed: bool = False
    interval_seconds: int = DEFAULT_WEEKLY_INTERVAL_SECONDS
    last_sent_at: Optional[datetime] = None
    next_run_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class NullSubscriptionStore:
    enabled = False

    def upsert_pending(
        self,
        host: str,
        port: int,
        email: str,
        plan: str = "free",
        interval_seconds: int = DEFAULT_WEEKLY_INTERVAL_SECONDS,
    ) -> MonitorSubscription:
        return MonitorSubscription(
            id=0,
            host=host,
            port=port,
            email=email,
            token=uuid4().hex,
            plan=normalize_plan(plan),
            interval_seconds=interval_seconds,
            next_run_at=utcnow() + timedelta(seconds=interval_seconds),
        )

    def confirm(self, token: str) -> Optional[MonitorSubscription]:
        return None

    def disable(self, token: str) -> Optional[MonitorSubscription]:
        return None

    def find_by_email(self, email: str) -> List[MonitorSubscription]:
        return []

    def get_by_id(self, subscription_id: int) -> Optional[MonitorSubscription]:
        return None

    def list_by_email(self, email: str, limit: int = 20) -> List[MonitorSubscription]:
        return []

    def begin_ownership_verification(
        self,
        subscription_id: int,
        method: str,
        token: str,
    ) -> Optional[MonitorSubscription]:
        return None

    def mark_ownership_verified(
        self,
        subscription_id: int,
        when: Optional[datetime] = None,
    ) -> Optional[MonitorSubscription]:
        return None

    def due(self, now: Optional[datetime] = None, limit: int = 20) -> List[MonitorSubscription]:
        return []

    def mark_sent(self, subscription_id: int, when: Optional[datetime] = None) -> None:
        return

    def should_send_report(self, subscription_id: int, scan_id: str) -> bool:
        return True

    def mark_report_sent(
        self,
        subscription_id: int,
        scan_id: str,
        when: Optional[datetime] = None,
    ) -> None:
        return

    def should_send_alert(
        self,
        subscription_id: int,
        alert_key: str,
        cooldown_seconds: int,
        now: Optional[datetime] = None,
    ) -> bool:
        return True

    def mark_alert_sent(
        self,
        subscription_id: int,
        alert_key: str,
        when: Optional[datetime] = None,
    ) -> None:
        return


class InMemorySubscriptionStore(NullSubscriptionStore):
    enabled = True

    def __init__(self) -> None:
        self.items: Dict[int, MonitorSubscription] = {}
        self.alert_sent: Dict[tuple[int, str], datetime] = {}
        self.report_sent: Dict[tuple[int, str], datetime] = {}
        self._id = 0

    def upsert_pending(
        self,
        host: str,
        port: int,
        email: str,
        plan: str = "free",
        interval_seconds: int = DEFAULT_WEEKLY_INTERVAL_SECONDS,
    ) -> MonitorSubscription:
        email_norm = normalize_email(email)
        now = utcnow()
        for item in self.items.values():
            if (
                normalize_email(item.email) == email_norm
                and item.host == host
                and item.port == port
            ):
                item.enabled = True
                item.confirmed = False
                item.plan = normalize_plan(plan)
                item.token = uuid4().hex
                item.ownership_method = ""
                item.ownership_token = ""
                item.ownership_verified_at = None
                item.interval_seconds = int(interval_seconds)
                item.next_run_at = now + timedelta(seconds=item.interval_seconds)
                item.updated_at = now
                return item
        self._id += 1
        sub = MonitorSubscription(
            id=self._id,
            host=host,
            port=port,
            email=email_norm,
            token=uuid4().hex,
            plan=normalize_plan(plan),
            ownership_method="",
            ownership_token="",
            ownership_verified_at=None,
            enabled=True,
            confirmed=False,
            interval_seconds=int(interval_seconds),
            next_run_at=now + timedelta(seconds=int(interval_seconds)),
            created_at=now,
            updated_at=now,
        )
        self.items[sub.id] = sub
        return sub

    def confirm(self, token: str) -> Optional[MonitorSubscription]:
        now = utcnow()
        for item in self.items.values():
            if item.token == token and item.enabled:
                item.confirmed = True
                item.updated_at = now
                return item
        return None

    def disable(self, token: str) -> Optional[MonitorSubscription]:
        now = utcnow()
        for item in self.items.values():
            if item.token == token and item.enabled:
                item.enabled = False
                item.updated_at = now
                return item
        return None

    def find_by_email(self, email: str) -> List[MonitorSubscription]:
        email_norm = normalize_email(email)
        return [item for item in self.items.values() if normalize_email(item.email) == email_norm]

    def get_by_id(self, subscription_id: int) -> Optional[MonitorSubscription]:
        return self.items.get(int(subscription_id))

    def list_by_email(self, email: str, limit: int = 20) -> List[MonitorSubscription]:
        email_norm = normalize_email(email)
        items = [item for item in self.items.values() if normalize_email(item.email) == email_norm]
        items.sort(key=lambda item: item.id, reverse=True)
        return items[: max(1, int(limit))]

    def begin_ownership_verification(
        self,
        subscription_id: int,
        method: str,
        token: str,
    ) -> Optional[MonitorSubscription]:
        item = self.items.get(int(subscription_id))
        if not item:
            return None
        item.ownership_method = str(method or "").strip().lower()
        item.ownership_token = str(token or "").strip()
        item.ownership_verified_at = None
        item.updated_at = utcnow()
        return item

    def mark_ownership_verified(
        self,
        subscription_id: int,
        when: Optional[datetime] = None,
    ) -> Optional[MonitorSubscription]:
        item = self.items.get(int(subscription_id))
        if not item:
            return None
        when = when or utcnow()
        item.ownership_verified_at = when
        item.updated_at = when
        return item

    def due(self, now: Optional[datetime] = None, limit: int = 20) -> List[MonitorSubscription]:
        now = now or utcnow()
        items = [
            item
            for item in self.items.values()
            if item.enabled
            and item.confirmed
            and item.next_run_at
            and item.next_run_at <= now
            and (
                item.plan == "free"
                or (item.plan == "support" and item.ownership_verified_at is not None)
            )
        ]
        items.sort(key=lambda item: item.next_run_at or now)
        return items[: max(1, int(limit))]

    def mark_sent(self, subscription_id: int, when: Optional[datetime] = None) -> None:
        item = self.items.get(int(subscription_id))
        if not item:
            return
        when = when or utcnow()
        item.last_sent_at = when
        item.next_run_at = when + timedelta(seconds=item.interval_seconds)
        item.updated_at = when

    def should_send_report(self, subscription_id: int, scan_id: str) -> bool:
        key = (int(subscription_id), str(scan_id))
        return key not in self.report_sent

    def mark_report_sent(
        self,
        subscription_id: int,
        scan_id: str,
        when: Optional[datetime] = None,
    ) -> None:
        when = when or utcnow()
        key = (int(subscription_id), str(scan_id))
        self.report_sent[key] = when

    def should_send_alert(
        self,
        subscription_id: int,
        alert_key: str,
        cooldown_seconds: int,
        now: Optional[datetime] = None,
    ) -> bool:
        now = now or utcnow()
        key = (int(subscription_id), str(alert_key).strip().lower())
        last = self.alert_sent.get(key)
        if last is None:
            return True
        return (now - last).total_seconds() >= max(0, int(cooldown_seconds))

    def mark_alert_sent(
        self,
        subscription_id: int,
        alert_key: str,
        when: Optional[datetime] = None,
    ) -> None:
        when = when or utcnow()
        key = (int(subscription_id), str(alert_key).strip().lower())
        self.alert_sent[key] = when


class PostgresSubscriptionStore(NullSubscriptionStore):
    enabled = True

    def __init__(self, database_url: str) -> None:
        self.database_url = database_url

    def upsert_pending(
        self,
        host: str,
        port: int,
        email: str,
        plan: str = "free",
        interval_seconds: int = DEFAULT_WEEKLY_INTERVAL_SECONDS,
    ) -> MonitorSubscription:
        email_norm = normalize_email(email)
        token = uuid4().hex
        with self.connect() as conn:
            row = conn.execute(
                """
                INSERT INTO monitor_subscriptions (
                    host, port, email, token, enabled, confirmed, interval_seconds,
                    next_run_at, plan, ownership_method, ownership_token, ownership_verified_at
                )
                VALUES (
                    %(host)s, %(port)s, %(email)s, %(token)s, true, false, %(interval_seconds)s,
                    now() + (%(interval_seconds)s * interval '1 second'), %(plan)s,
                    '', '', NULL
                )
                ON CONFLICT (email, host, port) DO UPDATE SET
                    token = EXCLUDED.token,
                    enabled = true,
                    confirmed = false,
                    plan = EXCLUDED.plan,
                    ownership_method = '',
                    ownership_token = '',
                    ownership_verified_at = NULL,
                    interval_seconds = EXCLUDED.interval_seconds,
                    next_run_at = EXCLUDED.next_run_at
                RETURNING *
                """,
                {
                    "host": host,
                    "port": int(port),
                    "email": email_norm,
                    "token": token,
                    "interval_seconds": int(interval_seconds),
                    "plan": normalize_plan(plan),
                },
            ).fetchone()
        return subscription_from_row(row)

    def confirm(self, token: str) -> Optional[MonitorSubscription]:
        with self.connect() as conn:
            row = conn.execute(
                """
                UPDATE monitor_subscriptions
                SET confirmed = true
                WHERE token = %(token)s AND enabled = true
                RETURNING *
                """,
                {"token": token},
            ).fetchone()
        return subscription_from_row(row) if row else None

    def disable(self, token: str) -> Optional[MonitorSubscription]:
        with self.connect() as conn:
            row = conn.execute(
                """
                UPDATE monitor_subscriptions
                SET enabled = false
                WHERE token = %(token)s
                RETURNING *
                """,
                {"token": token},
            ).fetchone()
        return subscription_from_row(row) if row else None

    def find_by_email(self, email: str) -> List[MonitorSubscription]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM monitor_subscriptions
                WHERE email = %(email)s
                ORDER BY id DESC
                """,
                {"email": normalize_email(email)},
            ).fetchall()
        return [subscription_from_row(row) for row in rows]

    def get_by_id(self, subscription_id: int) -> Optional[MonitorSubscription]:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM monitor_subscriptions
                WHERE id = %(id)s
                LIMIT 1
                """,
                {"id": int(subscription_id)},
            ).fetchone()
        return subscription_from_row(row) if row else None

    def list_by_email(self, email: str, limit: int = 20) -> List[MonitorSubscription]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM monitor_subscriptions
                WHERE email = %(email)s
                ORDER BY id DESC
                LIMIT %(limit)s
                """,
                {"email": normalize_email(email), "limit": max(1, int(limit))},
            ).fetchall()
        return [subscription_from_row(row) for row in rows]

    def due(self, now: Optional[datetime] = None, limit: int = 20) -> List[MonitorSubscription]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM monitor_subscriptions
                WHERE enabled = true
                  AND confirmed = true
                  AND (
                    plan = 'free'
                    OR (plan = 'support' AND ownership_verified_at IS NOT NULL)
                  )
                  AND next_run_at <= coalesce(%(now)s, now())
                ORDER BY next_run_at ASC
                LIMIT %(limit)s
                """,
                {"now": now, "limit": max(1, int(limit))},
            ).fetchall()
        return [subscription_from_row(row) for row in rows]

    def begin_ownership_verification(
        self,
        subscription_id: int,
        method: str,
        token: str,
    ) -> Optional[MonitorSubscription]:
        with self.connect() as conn:
            row = conn.execute(
                """
                UPDATE monitor_subscriptions
                SET ownership_method = %(method)s,
                    ownership_token = %(token)s,
                    ownership_verified_at = NULL
                WHERE id = %(id)s
                RETURNING *
                """,
                {
                    "id": int(subscription_id),
                    "method": str(method or "").strip().lower(),
                    "token": str(token or "").strip(),
                },
            ).fetchone()
        return subscription_from_row(row) if row else None

    def mark_ownership_verified(
        self,
        subscription_id: int,
        when: Optional[datetime] = None,
    ) -> Optional[MonitorSubscription]:
        when = when or utcnow()
        with self.connect() as conn:
            row = conn.execute(
                """
                UPDATE monitor_subscriptions
                SET ownership_verified_at = %(when)s
                WHERE id = %(id)s
                RETURNING *
                """,
                {"id": int(subscription_id), "when": when},
            ).fetchone()
        return subscription_from_row(row) if row else None

    def mark_sent(self, subscription_id: int, when: Optional[datetime] = None) -> None:
        when = when or utcnow()
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE monitor_subscriptions
                SET last_sent_at = %(when)s,
                    next_run_at = %(when)s + (interval_seconds * interval '1 second')
                WHERE id = %(id)s
                """,
                {"id": int(subscription_id), "when": when},
            )

    def should_send_report(self, subscription_id: int, scan_id: str) -> bool:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT 1
                FROM subscription_report_deliveries
                WHERE subscription_id = %(subscription_id)s
                  AND scan_id = %(scan_id)s
                LIMIT 1
                """,
                {"subscription_id": int(subscription_id), "scan_id": str(scan_id)},
            ).fetchone()
        return row is None

    def mark_report_sent(
        self,
        subscription_id: int,
        scan_id: str,
        when: Optional[datetime] = None,
    ) -> None:
        when = when or utcnow()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO subscription_report_deliveries (subscription_id, scan_id, sent_at)
                VALUES (%(subscription_id)s, %(scan_id)s, %(sent_at)s)
                ON CONFLICT (subscription_id, scan_id) DO NOTHING
                """,
                {
                    "subscription_id": int(subscription_id),
                    "scan_id": str(scan_id),
                    "sent_at": when,
                },
            )

    def connect(self):
        import psycopg
        from psycopg.rows import dict_row

        return psycopg.connect(self.database_url, row_factory=dict_row)

    def should_send_alert(
        self,
        subscription_id: int,
        alert_key: str,
        cooldown_seconds: int,
        now: Optional[datetime] = None,
    ) -> bool:
        now = now or utcnow()
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT last_sent_at
                FROM subscription_alert_deliveries
                WHERE subscription_id = %(subscription_id)s
                  AND alert_key = %(alert_key)s
                LIMIT 1
                """,
                {
                    "subscription_id": int(subscription_id),
                    "alert_key": str(alert_key).strip().lower(),
                },
            ).fetchone()
        if not row or not row.get("last_sent_at"):
            return True
        last_sent_at = row["last_sent_at"]
        return (now - last_sent_at).total_seconds() >= max(0, int(cooldown_seconds))

    def mark_alert_sent(
        self,
        subscription_id: int,
        alert_key: str,
        when: Optional[datetime] = None,
    ) -> None:
        when = when or utcnow()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO subscription_alert_deliveries (subscription_id, alert_key, last_sent_at)
                VALUES (%(subscription_id)s, %(alert_key)s, %(last_sent_at)s)
                ON CONFLICT (subscription_id, alert_key) DO UPDATE SET
                    last_sent_at = EXCLUDED.last_sent_at
                """,
                {
                    "subscription_id": int(subscription_id),
                    "alert_key": str(alert_key).strip().lower(),
                    "last_sent_at": when,
                },
            )


def create_subscription_store(database_url: str = ""):
    if database_url:
        return PostgresSubscriptionStore(database_url)
    return InMemorySubscriptionStore()


def normalize_email(value: str) -> str:
    return value.strip().lower()


def normalize_plan(value: str) -> str:
    normalized = str(value or "free").strip().lower()
    if normalized == "pro":
        return "support"
    if normalized not in {"free", "support"}:
        return "free"
    return normalized


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def subscription_from_row(row: Dict[str, object]) -> MonitorSubscription:
    return MonitorSubscription(
        id=int(row["id"]),
        host=str(row["host"]),
        port=int(row["port"]),
        email=str(row["email"]),
        token=str(row["token"]),
        plan=normalize_plan(row.get("plan") or "free"),
        ownership_method=str(row.get("ownership_method") or ""),
        ownership_token=str(row.get("ownership_token") or ""),
        ownership_verified_at=row.get("ownership_verified_at"),
        enabled=bool(row["enabled"]),
        confirmed=bool(row["confirmed"]),
        interval_seconds=int(row["interval_seconds"]),
        last_sent_at=row.get("last_sent_at"),
        next_run_at=row.get("next_run_at"),
        created_at=row.get("created_at"),
        updated_at=row.get("updated_at"),
    )
