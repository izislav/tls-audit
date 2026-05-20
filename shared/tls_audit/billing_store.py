from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Optional


@dataclass
class BillingAccount:
    email: str
    plan: str = "free"
    status: str = "inactive"
    domain_limit: int = 1
    checkout_id: str = ""
    provider: str = "manual"
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class NullBillingStore:
    enabled = False

    def create_checkout(self, email: str, checkout_id: str) -> BillingAccount:
        return BillingAccount(email=normalize_email(email), checkout_id=checkout_id, status="pending")

    def activate_pro(self, email: str) -> BillingAccount:
        return BillingAccount(
            email=normalize_email(email),
            plan="support",
            status="active",
            domain_limit=10,
        )

    def get_by_email(self, email: str) -> Optional[BillingAccount]:
        return None


class InMemoryBillingStore(NullBillingStore):
    enabled = True

    def __init__(self) -> None:
        self.items: Dict[str, BillingAccount] = {}

    def create_checkout(self, email: str, checkout_id: str) -> BillingAccount:
        now = utcnow()
        key = normalize_email(email)
        item = self.items.get(key) or BillingAccount(email=key, created_at=now)
        item.checkout_id = checkout_id
        item.status = "pending"
        item.updated_at = now
        self.items[key] = item
        return item

    def activate_pro(self, email: str) -> BillingAccount:
        now = utcnow()
        key = normalize_email(email)
        item = self.items.get(key) or BillingAccount(email=key, created_at=now)
        item.plan = "support"
        item.status = "active"
        item.domain_limit = 10
        item.updated_at = now
        self.items[key] = item
        return item

    def get_by_email(self, email: str) -> Optional[BillingAccount]:
        return self.items.get(normalize_email(email))


class PostgresBillingStore(NullBillingStore):
    enabled = True

    def __init__(self, database_url: str) -> None:
        self.database_url = database_url

    def create_checkout(self, email: str, checkout_id: str) -> BillingAccount:
        with self.connect() as conn:
            row = conn.execute(
                """
                INSERT INTO billing_accounts (email, plan, status, domain_limit, checkout_id, provider)
                VALUES (%(email)s, 'free', 'pending', 1, %(checkout_id)s, 'manual')
                ON CONFLICT (email) DO UPDATE SET
                    checkout_id = EXCLUDED.checkout_id,
                    status = 'pending',
                    updated_at = now()
                RETURNING *
                """,
                {"email": normalize_email(email), "checkout_id": checkout_id},
            ).fetchone()
        return billing_from_row(row)

    def activate_pro(self, email: str) -> BillingAccount:
        with self.connect() as conn:
            row = conn.execute(
                """
                INSERT INTO billing_accounts (email, plan, status, domain_limit, provider)
                VALUES (%(email)s, 'support', 'active', 10, 'manual')
                ON CONFLICT (email) DO UPDATE SET
                    plan = 'support',
                    status = 'active',
                    domain_limit = 10,
                    updated_at = now()
                RETURNING *
                """,
                {"email": normalize_email(email)},
            ).fetchone()
        return billing_from_row(row)

    def get_by_email(self, email: str) -> Optional[BillingAccount]:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM billing_accounts
                WHERE email = %(email)s
                LIMIT 1
                """,
                {"email": normalize_email(email)},
            ).fetchone()
        return billing_from_row(row) if row else None

    def connect(self):
        import psycopg
        from psycopg.rows import dict_row

        return psycopg.connect(self.database_url, row_factory=dict_row)


def create_billing_store(database_url: str = ""):
    if database_url:
        return PostgresBillingStore(database_url)
    return InMemoryBillingStore()


def normalize_email(value: str) -> str:
    return str(value).strip().lower()


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def billing_from_row(row: Dict[str, object]) -> BillingAccount:
    return BillingAccount(
        email=str(row["email"]),
        plan=str(row.get("plan") or "free"),
        status=str(row.get("status") or "inactive"),
        domain_limit=int(row.get("domain_limit") or 1),
        checkout_id=str(row.get("checkout_id") or ""),
        provider=str(row.get("provider") or "manual"),
        created_at=row.get("created_at"),
        updated_at=row.get("updated_at"),
    )
