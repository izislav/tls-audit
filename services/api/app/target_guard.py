from shared.tls_audit.traffic_control import TargetScanGuard

from .settings import settings


target_scan_guard = TargetScanGuard(
    redis_url=settings.redis_url,
    cooldown_seconds=settings.target_cooldown_seconds,
    active_ttl_seconds=settings.active_scan_ttl_seconds,
)
