import json
import os
from typing import Dict

from .settings import settings


DEV_QUEUE_FILE = os.getenv("DEV_QUEUE_FILE", "/tmp/tls-audit-jobs.jsonl")


def enqueue_scan_job(payload: Dict[str, object]) -> None:
    if settings.redis_url:
        import redis

        client = redis.from_url(settings.redis_url)
        client.rpush(settings.scan_queue_name, json.dumps(payload, ensure_ascii=False))
        return

    # Local fallback for early development when Redis is not running.
    with open(DEV_QUEUE_FILE, "a", encoding="utf-8") as queue_file:
        queue_file.write(json.dumps(payload, ensure_ascii=False) + "\n")


def queue_depth() -> int:
    if settings.redis_url:
        import redis

        client = redis.from_url(settings.redis_url)
        return int(client.llen(settings.scan_queue_name))

    try:
        with open(DEV_QUEUE_FILE, "r", encoding="utf-8") as queue_file:
            return sum(1 for line in queue_file if line.strip())
    except FileNotFoundError:
        return 0
