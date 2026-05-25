from shared.tls_audit.subscription_store import create_subscription_store

from .settings import settings


subscription_store = create_subscription_store(settings.database_url)
