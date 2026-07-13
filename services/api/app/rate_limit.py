from shared.tls_audit.traffic_control import RollingRateLimiter

from .settings import settings


rate_limiter = RollingRateLimiter(
    redis_url=settings.redis_url,
    limit=settings.rate_limit_per_minute,
    window_seconds=60,
    captcha_after=settings.captcha_after_per_minute,
)

monitoring_rate_limiter = RollingRateLimiter(
    redis_url=settings.redis_url,
    limit=settings.monitoring_rate_limit,
    window_seconds=settings.monitoring_rate_window_seconds,
    prefix="tls-audit-monitoring",
)

email_rate_limiter = RollingRateLimiter(
    redis_url=settings.redis_url,
    limit=settings.email_rate_limit,
    window_seconds=settings.email_rate_window_seconds,
    prefix="tls-audit-email",
)
