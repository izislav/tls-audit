from shared.tls_audit.denylist import Denylist

from .settings import settings


denylist = Denylist.from_text(
    client_ips=settings.blocked_client_ips,
    targets=settings.blocked_targets,
)
