# TLS Audit — Full Code and Production Audit

Date: 2026-06-01  
Scope: local codebase, tests, Docker build path, Git state, VPS runtime, PostgreSQL, public endpoints

## 1) Executive Summary

Service state: working and stable for the current v0.2 baseline.

Production is healthy:

- `https://tlsaudit.ru/` returns `200`;
- `/health` returns `{"status":"ok","database":"enabled"}`;
- public monitoring admin endpoints return `404` without a valid admin token;
- SSRF guard blocks `127.0.0.1` scan attempts with `400`;
- Docker services are up: `api`, `worker`, `scheduler`, `redis`, `postgres`;
- Redis queue length is `0`;
- latest production scans complete successfully.

Main code issue found and fixed:

- report cleanup could delete scans referenced by `monitoring_snapshots`; because the DB relation uses `ON DELETE CASCADE`, this could erase monitoring history. Cleanup now preserves scan rows that have monitoring snapshots.

Build/test issue found and fixed:

- `fastapi.testclient` requires `httpx`, but `httpx` was not pinned in test dependencies. Added a separate test requirements file so API/UI smoke tests run in container/CI without changing production runtime dependencies.

Repo hygiene issue found and fixed:

- local VPS baseline archive and macOS AppleDouble files were entering Docker build context. Added `.dockerignore` and extended `.gitignore`.

Deployment issue found and fixed:

- VPS Docker build was sensitive to PyPI read timeouts. Dockerfiles now use explicit pip timeout/retry settings.

## 2) Local Code State

Before audit changes:

- branch: `main`;
- local branch was aligned with `origin/main`;
- only untracked local artifact was `_vps_baseline_20260518/`;
- latest committed v0.2 docs baseline was `2ff9675`.

Validation performed:

- local Python fallback: `python3 -m unittest discover -q`;
- result: `117 tests OK`, with local dependency skips before Docker validation;
- Docker validation after dependency fix: `117 tests OK`;
- API Docker build works after `.dockerignore`;
- Docker build context reduced from about `29 MB` to about `148 kB`.

## 3) Production State

Host:

- hostname: `box`;
- uptime: 38+ days at audit time;
- load average: `0.19, 0.12, 0.10`.

Disk:

- root filesystem: `30G`;
- used: `16G`;
- available: `13G`;
- usage: `55%`.

Largest relevant storage:

- Docker images: `785.8 MB`;
- Docker volumes: `76.04 MB`;
- `/var/log`: `601 MB`;
- `/var/log/journal`: `307 MB`;
- `/opt/tls-audit`: `17 MB`;
- PostgreSQL database: `12 MB`.

Production containers:

- `tls-audit-api-1`: up, healthy;
- `tls-audit-worker-1`: up, healthy;
- `tls-audit-scheduler-1`: up;
- `tls-audit-postgres-1`: up, healthy;
- `tls-audit-redis-1`: up, healthy.

Production Git state:

- branch: `main`;
- deployed commit at audit time: `69bd9a2`;
- current local/GitHub documentation baseline was newer;
- production working tree contains old untracked macOS `._*` files and backup/env artifacts. They do not affect runtime, but should be cleaned during a controlled maintenance window.

## 4) Production Database Snapshot

Counts at audit time:

- scans: `69`;
- reports: `69`;
- monitor subscriptions: `5`;
- monitoring snapshots: `21`;
- monitoring events: `0`;
- alert deliveries: `2`;
- report deliveries: `14`.

Table sizes:

- `reports`: `2672 kB`;
- `findings`: `816 kB`;
- `scans`: `120 kB`;
- `monitoring_snapshots`: `104 kB`;
- `monitor_subscriptions`: `80 kB`;
- other operational tables: `16-64 kB`.

Subscription state:

- `nrdrive.ru`: Pro/support, confirmed, ownership verified, next run `2026-06-05`;
- `star-smile.ru`: Pro/support, confirmed, ownership verified, next run `2026-06-04`;
- three older pending/unconfirmed `star-smile.ru` subscriptions remain enabled but unconfirmed. They are ignored by the scheduler because `confirmed=false`, but should be cleaned later for database hygiene.

Latest production scans:

- `nrdrive.ru`: done, grade `B`, score `70`;
- `star-smile.ru`: done, grade `B`, score `80`;
- worker logs show repeated successful scan start/done cycles.

Events:

- event pipeline exists;
- production currently has `0` persisted monitoring events because recent monitored changes did not trigger event rules such as grade degradation, certificate expiry, critical/high added finding, legacy TLS enabled, or scan failure.

## 5) Public Endpoint Audit

Checked endpoints:

- `GET /`: `200`;
- `GET /health`: `200`;
- `GET /robots.txt`: `200`;
- `GET /sitemap.xml`: `200`;
- `GET /api/report/not-a-real-job`: `404`;
- `GET /api/monitor/domains`: `404`;
- `GET /api/monitor/domains` with wrong admin token: `404`;
- `GET /api/monitor/domains/1/events` with wrong admin token: `404`;
- `POST /api/check` with `127.0.0.1`: `400`.

Conclusion:

- public surface is responding;
- private/admin monitoring API is not exposed without token;
- obvious localhost SSRF attempt is blocked.

## 6) Changes Made In This Audit

Code:

- `shared/tls_audit/archive.py`
  - changed report cleanup to preserve scans referenced by `monitoring_snapshots`;
  - prevents accidental loss of monitoring history.

Tests:

- `tests/test_archive_cleanup.py`
  - added regression test for monitoring-snapshot preservation during cleanup.

Dependencies:

- `requirements/test.txt`
  - added `httpx==0.27.2` for FastAPI/Starlette TestClient.

CI:

- `.github/workflows/ci.yml`
  - normalized GitHub Actions test workflow for pushes and PRs to `main`;
  - added explicit test environment variables and timeout.

Repo/Docker hygiene:

- `.gitignore`
  - ignores `.env.*`, logs, macOS `._*`, and local VPS baseline artifacts.
- `.dockerignore`
  - excludes Git metadata, local env/backups/logs/cache/archive artifacts from Docker build context.
- `deploy/Dockerfile.api`, `deploy/Dockerfile.worker`
  - use explicit pip retries and longer timeout for more reliable VPS builds.

## 7) Remaining Risks

1. Production is one code step behind current local/GitHub audit fixes until the new commit is deployed.
2. Production working tree contains many untracked `._*` files from macOS copy operations. They are harmless but noisy.
3. Pending/unconfirmed subscriptions remain in DB. This is not a runtime issue, but cleanup policy is needed.
4. Monitoring events are implemented, but production has not yet recorded real events; this should be verified with a controlled synthetic event test before calling alerting fully proven.
5. `/var/log/journal` is not currently dangerous (`307 MB`), but should have an explicit retention cap.
6. Payment/billing is still not connected; Pro currently works as functional/free support mode.

## 8) Development Plan From Current State

Priority 1 — finish production hygiene:

- deploy current audit fixes to VPS;
- clean ignored macOS `._*` files during maintenance;
- optionally remove old pending unconfirmed subscriptions older than a chosen threshold;
- set or verify journald retention cap.

Priority 2 — prove event alerts end to end:

- add a safe synthetic event test path or fixture;
- verify email alert for `scan_failed`;
- verify email alert for `certificate_expiring`;
- verify email alert for `grade_degraded`;
- record the test result in docs.

Priority 3 — improve trust/product clarity:

- publish method version `0.2` consistently in UI/docs;
- make evidence readable for admins without exposing raw scanner noise;
- keep public report links stable and human-readable enough for support.

Priority 4 — Pro product hardening:

- cleanup stale pending subscriptions;
- finalize ownership UX;
- add export package for Pro report: JSON/CSV first, PDF later;
- add billing only after alerting/digest/report behavior is stable.

Priority 5 — operational automation:

- keep GitHub CI green;
- add a deployment checklist gate: backup -> pull -> build -> schema -> smoke -> endpoint checks;
- add periodic DB/table-size report;
- add backup restore drill.

## 9) Current Verdict

TLS Audit is usable as a public v0.2 diagnostic and monitoring baseline.

The biggest technical gap before calling the next version stable is not the scanner. It is operational proof of alert behavior: controlled event generation, confirmed alert delivery, and cleanup policies for old/pending monitoring data.
