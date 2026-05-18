from shared.tls_audit.monitoring_store import create_monitoring_store

from .settings import settings


monitoring_store = create_monitoring_store(settings.database_url)
