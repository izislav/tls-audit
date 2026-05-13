from shared.tls_audit.traffic_control import RollingRateLimiter

from .settings import settings


rate_limiter = RollingRateLimiter(
    redis_url=settings.redis_url,
    limit=settings.rate_limit_per_minute,
    window_seconds=60,
    captcha_after=settings.captcha_after_per_minute,
)
