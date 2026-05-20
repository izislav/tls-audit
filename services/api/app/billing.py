from shared.tls_audit.billing_store import create_billing_store

from .settings import settings


billing_store = create_billing_store(settings.database_url)
