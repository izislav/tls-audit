import base64
import hashlib
import hmac
import secrets
import time
from typing import Optional


DEFAULT_OWNER_TOKEN_TTL_SECONDS = 24 * 60 * 60


def build_monitor_token_secret(
    *,
    monitoring_token_secret: str,
    database_url: str,
    redis_url: str,
    public_base_url: str,
    contact_email: str,
    require_explicit: bool = False,
) -> str:
    if monitoring_token_secret:
        return monitoring_token_secret
    if require_explicit:
        raise RuntimeError("MONITORING_TOKEN_SECRET is required in production.")
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


def create_monitor_owner_token(
    email: str,
    secret: str,
    *,
    issued_at: Optional[int] = None,
) -> str:
    normalized = email.strip().lower()
    timestamp = int(time.time() if issued_at is None else issued_at)
    signed_value = f"m2|{timestamp}|{normalized}"
    signature = hmac.new(
        secret.encode("utf-8"),
        signed_value.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    raw = f"{signed_value}|{signature}".encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def email_from_monitor_owner_token(
    token: str,
    secret: str,
    *,
    max_age_seconds: int = DEFAULT_OWNER_TOKEN_TTL_SECONDS,
    now: Optional[int] = None,
) -> Optional[str]:
    value = str(token or "").strip()
    if not value:
        return None
    padding = "=" * (-len(value) % 4)
    try:
        decoded = base64.urlsafe_b64decode(value + padding).decode("utf-8")
    except Exception:  # noqa: BLE001
        return None
    parts = decoded.split("|")
    if len(parts) != 4 or parts[0] != "m2":
        return None
    _prefix, issued_text, email, signature = parts
    if not issued_text or not email or not signature:
        return None
    try:
        issued_at = int(issued_text)
    except ValueError:
        return None
    current = int(time.time() if now is None else now)
    ttl = max(1, int(max_age_seconds))
    if issued_at > current + 60 or current - issued_at > ttl:
        return None
    signed_value = f"m2|{issued_at}|{email}"
    expected = hmac.new(
        secret.encode("utf-8"),
        signed_value.encode("utf-8"),
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
