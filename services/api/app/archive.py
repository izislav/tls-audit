from shared.tls_audit.archive import create_archive_store

from .settings import settings


archive_store = create_archive_store(settings.database_url)
