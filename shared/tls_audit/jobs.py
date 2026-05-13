import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional


@dataclass
class JobRecord:
    id: str
    host: str
    port: int
    addresses: List[str] = field(default_factory=list)
    status: str = "queued"
    progress_percent: int = 0
    progress_stage: str = "queued"
    progress_detail: str = "Ожидаем worker"
    error: str = ""
    report: Optional[Dict[str, object]] = None
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, object]) -> "JobRecord":
        return cls(
            id=str(data["id"]),
            host=str(data["host"]),
            port=int(data["port"]),
            addresses=list(data.get("addresses") or []),
            status=str(data.get("status") or "queued"),
            progress_percent=int(data.get("progress_percent") or 0),
            progress_stage=str(data.get("progress_stage") or "queued"),
            progress_detail=str(data.get("progress_detail") or "Ожидаем worker"),
            error=str(data.get("error") or ""),
            report=data.get("report"),
            created_at=float(data.get("created_at") or time.time()),
            updated_at=float(data.get("updated_at") or time.time()),
        )


class InMemoryJobStore:
    def __init__(self) -> None:
        self.jobs: Dict[str, JobRecord] = {}

    def create(self, host: str, port: int, addresses: Optional[List[str]] = None) -> JobRecord:
        job = JobRecord(id=uuid.uuid4().hex, host=host, port=port, addresses=addresses or [])
        self.jobs[job.id] = job
        return job

    def get(self, job_id: str) -> Optional[JobRecord]:
        return self.jobs.get(job_id)

    def save(self, job: JobRecord) -> JobRecord:
        job.updated_at = time.time()
        self.jobs[job.id] = job
        return job

    def update(self, job_id: str, **changes: object) -> Optional[JobRecord]:
        job = self.get(job_id)
        if not job:
            return None
        for key, value in changes.items():
            setattr(job, key, value)
        return self.save(job)

    def delete(self, job_id: str) -> None:
        self.jobs.pop(job_id, None)

    def clear(self) -> None:
        self.jobs.clear()


class RedisJobStore:
    def __init__(self, redis_url: str, prefix: str = "tls-audit") -> None:
        self.redis_url = redis_url
        self.prefix = prefix
        self._client = None

    @property
    def client(self):
        if self._client is None:
            import redis

            self._client = redis.from_url(self.redis_url, decode_responses=True)
        return self._client

    def key(self, job_id: str) -> str:
        return f"{self.prefix}:job:{job_id}"

    def create(self, host: str, port: int, addresses: Optional[List[str]] = None) -> JobRecord:
        job = JobRecord(id=uuid.uuid4().hex, host=host, port=port, addresses=addresses or [])
        return self.save(job)

    def get(self, job_id: str) -> Optional[JobRecord]:
        import json

        payload = self.client.get(self.key(job_id))
        if not payload:
            return None
        return JobRecord.from_dict(json.loads(payload))

    def save(self, job: JobRecord) -> JobRecord:
        import json

        job.updated_at = time.time()
        self.client.set(self.key(job.id), json.dumps(job.to_dict(), ensure_ascii=False))
        return job

    def update(self, job_id: str, **changes: object) -> Optional[JobRecord]:
        job = self.get(job_id)
        if not job:
            return None
        for key, value in changes.items():
            setattr(job, key, value)
        return self.save(job)

    def delete(self, job_id: str) -> None:
        self.client.delete(self.key(job_id))

    def clear(self) -> None:
        cursor = 0
        pattern = f"{self.prefix}:job:*"
        while True:
            cursor, keys = self.client.scan(cursor=cursor, match=pattern, count=100)
            if keys:
                self.client.delete(*keys)
            if cursor == 0:
                break


def create_job_store(redis_url: str = ""):
    if redis_url:
        return RedisJobStore(redis_url)
    return InMemoryJobStore()

