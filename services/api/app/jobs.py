from shared.tls_audit.jobs import create_job_store

from .settings import settings


job_store = create_job_store(settings.redis_url)
