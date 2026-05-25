import os
from dataclasses import dataclass


@dataclass
class Settings:
    public_base_url: str = os.getenv("PUBLIC_BASE_URL", "https://tlsaudit.ru").rstrip("/")
    redis_url: str = os.getenv("REDIS_URL", "")
    database_url: str = os.getenv("DATABASE_URL", "")
    scan_queue_name: str = os.getenv("SCAN_QUEUE_NAME", "tls-audit:scan-jobs")
    max_scan_seconds: int = int(os.getenv("MAX_SCAN_SECONDS", "45"))
    rate_limit_per_minute: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "20"))
    captcha_after_per_minute: int = int(os.getenv("CAPTCHA_AFTER_PER_MINUTE", "15"))
    target_cooldown_seconds: int = int(os.getenv("TARGET_COOLDOWN_SECONDS", "30"))
    active_scan_ttl_seconds: int = int(os.getenv("ACTIVE_SCAN_TTL_SECONDS", "900"))
    max_queue_depth: int = int(os.getenv("MAX_QUEUE_DEPTH", "50"))
    blocked_client_ips: str = os.getenv("BLOCKED_CLIENT_IPS", "")
    blocked_targets: str = os.getenv("BLOCKED_TARGETS", "")
    trust_proxy_headers: bool = os.getenv("TRUST_PROXY_HEADERS", "false").lower() == "true"
    report_retention_days: int = int(os.getenv("REPORT_RETENTION_DAYS", "30"))
    error_retention_days: int = int(os.getenv("ERROR_RETENTION_DAYS", "7"))
    yandex_verification_file: str = os.getenv("YANDEX_VERIFICATION_FILE", "").strip()
    yandex_verification_content: str = os.getenv("YANDEX_VERIFICATION_CONTENT", "").strip()
    google_verification_file: str = os.getenv("GOOGLE_VERIFICATION_FILE", "").strip()
    google_verification_content: str = os.getenv("GOOGLE_VERIFICATION_CONTENT", "").strip()
    contact_email: str = os.getenv("CONTACT_EMAIL", "info@tlsaudit.ru").strip()
    monitoring_token_secret: str = os.getenv("MONITORING_TOKEN_SECRET", "").strip()
    monitoring_admin_token: str = os.getenv("MONITORING_ADMIN_TOKEN", "").strip()


settings = Settings()
