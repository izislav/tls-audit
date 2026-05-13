import hashlib
import math
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, Optional, Tuple


@dataclass
class AdmissionDecision:
    allowed: bool
    reason: str = ""
    retry_after: int = 0
    captcha_required: bool = False
    job_id: str = ""


class RollingRateLimiter:
    def __init__(
        self,
        redis_url: str = "",
        limit: int = 20,
        window_seconds: int = 60,
        captcha_after: int = 0,
        prefix: str = "tls-audit",
    ) -> None:
        self.redis_url = redis_url
        self.limit = limit
        self.window_seconds = window_seconds
        self.captcha_after = captcha_after
        self.prefix = prefix
        self._client = None
        self._memory_hits: Dict[str, Deque[float]] = defaultdict(deque)

    @property
    def client(self):
        if self._client is None:
            import redis

            self._client = redis.from_url(self.redis_url, decode_responses=True)
        return self._client

    def allow(self, key: str) -> bool:
        return self.check(key).allowed

    def check(self, key: str) -> AdmissionDecision:
        if self.limit <= 0:
            return AdmissionDecision(allowed=True)
        if self.redis_url:
            return self._check_redis(key)
        return self._check_memory(key)

    def _check_memory(self, key: str) -> AdmissionDecision:
        now = time.time()
        window_start = now - self.window_seconds
        bucket = self._memory_hits[key]
        while bucket and bucket[0] < window_start:
            bucket.popleft()
        bucket.append(now)
        count = len(bucket)
        retry_after = retry_after_from_oldest(bucket[0], now, self.window_seconds)
        return AdmissionDecision(
            allowed=count <= self.limit,
            reason="rate_limit" if count > self.limit else "",
            retry_after=retry_after if count > self.limit else 0,
            captcha_required=self.captcha_after > 0 and count > self.captcha_after,
        )

    def _check_redis(self, key: str) -> AdmissionDecision:
        now = time.time()
        now_ms = int(now * 1000)
        window_ms = self.window_seconds * 1000
        redis_key = self._rate_key(key)
        member = f"{now_ms}-{uuid.uuid4().hex}"
        pipe = self.client.pipeline()
        pipe.zremrangebyscore(redis_key, 0, now_ms - window_ms)
        pipe.zadd(redis_key, {member: now_ms})
        pipe.zcard(redis_key)
        pipe.expire(redis_key, self.window_seconds * 2)
        _removed, _added, count, _expire = pipe.execute()

        retry_after = 0
        if count > self.limit:
            oldest = self.client.zrange(redis_key, 0, 0, withscores=True)
            if oldest:
                retry_after = retry_after_from_oldest(
                    float(oldest[0][1]) / 1000,
                    now,
                    self.window_seconds,
                )

        return AdmissionDecision(
            allowed=count <= self.limit,
            reason="rate_limit" if count > self.limit else "",
            retry_after=retry_after,
            captcha_required=self.captcha_after > 0 and count > self.captcha_after,
        )

    def _rate_key(self, key: str) -> str:
        return f"{self.prefix}:rate:{stable_digest(key)}"


class TargetScanGuard:
    def __init__(
        self,
        redis_url: str = "",
        cooldown_seconds: int = 30,
        active_ttl_seconds: int = 900,
        prefix: str = "tls-audit",
    ) -> None:
        self.redis_url = redis_url
        self.cooldown_seconds = cooldown_seconds
        self.active_ttl_seconds = active_ttl_seconds
        self.prefix = prefix
        self._client = None
        self._memory_active: Dict[str, Tuple[str, float]] = {}
        self._memory_cooldown: Dict[str, Tuple[str, float]] = {}

    @property
    def client(self):
        if self._client is None:
            import redis

            self._client = redis.from_url(self.redis_url, decode_responses=True)
        return self._client

    def reserve(self, host: str, port: int, job_id: str) -> AdmissionDecision:
        if self.redis_url:
            return self._reserve_redis(host, port, job_id)
        return self._reserve_memory(host, port, job_id)

    def release(self, host: str, port: int, job_id: str, cooldown: bool = True) -> None:
        if self.redis_url:
            self._release_redis(host, port, job_id, cooldown)
            return
        self._release_memory(host, port, job_id, cooldown)

    def _reserve_memory(self, host: str, port: int, job_id: str) -> AdmissionDecision:
        now = time.time()
        key = self._target_digest(host, port)
        self._purge_memory(now)
        cooldown = self._memory_cooldown.get(key)
        if cooldown:
            active_job, expires_at = cooldown
            return AdmissionDecision(
                allowed=False,
                reason="cooldown",
                retry_after=max(1, math.ceil(expires_at - now)),
                job_id=active_job,
            )
        active = self._memory_active.get(key)
        if active:
            active_job, expires_at = active
            return AdmissionDecision(
                allowed=False,
                reason="active",
                retry_after=max(1, math.ceil(expires_at - now)),
                job_id=active_job,
            )
        if self.active_ttl_seconds > 0:
            self._memory_active[key] = (job_id, now + self.active_ttl_seconds)
        return AdmissionDecision(allowed=True)

    def _release_memory(self, host: str, port: int, job_id: str, cooldown: bool) -> None:
        now = time.time()
        key = self._target_digest(host, port)
        active = self._memory_active.get(key)
        if active and active[0] == job_id:
            self._memory_active.pop(key, None)
        if cooldown and self.cooldown_seconds > 0:
            self._memory_cooldown[key] = (job_id, now + self.cooldown_seconds)

    def _purge_memory(self, now: float) -> None:
        self._memory_active = {
            key: value for key, value in self._memory_active.items() if value[1] > now
        }
        self._memory_cooldown = {
            key: value for key, value in self._memory_cooldown.items() if value[1] > now
        }

    def _reserve_redis(self, host: str, port: int, job_id: str) -> AdmissionDecision:
        active_key, cooldown_key = self._target_keys(host, port)
        cooldown_ttl = self.client.ttl(cooldown_key)
        if cooldown_ttl and cooldown_ttl > 0:
            return AdmissionDecision(
                allowed=False,
                reason="cooldown",
                retry_after=cooldown_ttl,
                job_id=self.client.get(cooldown_key) or "",
            )

        reserved = self.client.set(
            active_key,
            job_id,
            nx=True,
            ex=max(1, self.active_ttl_seconds),
        )
        if not reserved:
            return AdmissionDecision(
                allowed=False,
                reason="active",
                retry_after=max(1, self.client.ttl(active_key)),
                job_id=self.client.get(active_key) or "",
            )
        return AdmissionDecision(allowed=True)

    def _release_redis(self, host: str, port: int, job_id: str, cooldown: bool) -> None:
        active_key, cooldown_key = self._target_keys(host, port)
        if self.client.get(active_key) == job_id:
            self.client.delete(active_key)
        if cooldown and self.cooldown_seconds > 0:
            self.client.set(cooldown_key, job_id, ex=self.cooldown_seconds)

    def _target_keys(self, host: str, port: int) -> Tuple[str, str]:
        digest = self._target_digest(host, port)
        return (
            f"{self.prefix}:target:active:{digest}",
            f"{self.prefix}:target:cooldown:{digest}",
        )

    def _target_digest(self, host: str, port: int) -> str:
        return stable_digest(f"{host.lower()}:{port}")


def stable_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]


def retry_after_from_oldest(oldest: float, now: float, window_seconds: int) -> int:
    return max(1, math.ceil((oldest + window_seconds) - now))
