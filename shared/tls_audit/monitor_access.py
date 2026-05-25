import base64
import hashlib
import hmac
import secrets
from typing import Optional


def build_monitor_token_secret(
    *,
    monitoring_token_secret: str,
    database_url: str,
    redis_url: str,
    public_base_url: str,
    contact_email: str,
) -> str:
    if monitoring_token_secret:
        return monitoring_token_secret
    return "|".join(
        part
        for part in (
            database_url,
            redis_url,
            public_base_url,
            contact_email,
            "tls-audit-monitoring-v1",
        )
        if part
    )


def create_monitor_owner_token(email: str, secret: str) -> str:
    normalized = email.strip().lower()
    payload = normalized.encode("utf-8")
    signature = hmac.new(
        secret.encode("utf-8"),
        payload,
        hashlib.sha256,
    ).hexdigest()
    raw = f"m1|{normalized}|{signature}".encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def email_from_monitor_owner_token(token: str, secret: str) -> Optional[str]:
    value = str(token or "").strip()
    if not value:
        return None
    padding = "=" * (-len(value) % 4)
    try:
        decoded = base64.urlsafe_b64decode(value + padding).decode("utf-8")
    except Exception:  # noqa: BLE001
        return None
    prefix, sep, rest = decoded.partition("|")
    if prefix != "m1" or not sep:
        return None
    email, sep, signature = rest.partition("|")
    if not sep or not email or not signature:
        return None
    expected = hmac.new(
        secret.encode("utf-8"),
        email.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    if not secrets.compare_digest(signature, expected):
        return None
    if "@" not in email or email.startswith("@") or email.endswith("@"):
        return None
    return email


def monitoring_admin_token_valid(expected: str, provided: Optional[str]) -> bool:
    if not expected:
        return False
    return secrets.compare_digest(str(provided or "").strip(), expected.strip())
