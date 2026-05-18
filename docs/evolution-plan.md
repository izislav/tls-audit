# TLS Audit Evolution Plan

## Direction

TLS Audit evolves from a one-shot HTTPS/TLS scanner into an intelligent
operational platform for TLS risk management.

The public scanner stays simple: enter a domain, get a clear Russian report.
The platform layer is built underneath it: registry, scheduled scans, history,
diffs, events, and later alerts or AI-assisted operational summaries.

## Working Mode

Development happens locally first.

Rules:

- do not change the production VPS while a feature is half-built;
- build one complete feature slice at a time;
- keep server deployment as a deliberate final step;
- run local tests and compile checks before deployment;
- commit and push tested work to GitHub before touching production;
- let the current production service continue running while local work is in progress.

Production deployment starts only when the feature is complete enough to run on
the VPS for real traffic.

## Stage 1 - Monitoring Core

Goal: add the operational backend spine without UI magic.

Stage 1 must answer:

- which domains are under monitoring;
- when each domain should be scanned next;
- what changed between checks;
- which events matter operationally.

### 1. Domain Registry

Add a durable registry of monitored targets.

Initial fields:

- `id`;
- `host`;
- `port`;
- `enabled`;
- `scan_interval_seconds`;
- `last_scan_at`;
- `next_scan_at`;
- `created_at`;
- `updated_at`;
- optional `notes`;
- optional `tags` later.

No accounts or multi-tenant model in Stage 1.

### 2. Scheduled Scans

Add a scheduler that finds due enabled domains and enqueues normal scan jobs.

Rules:

- respect `next_scan_at`;
- avoid duplicate active scans for the same `host:port`;
- record trigger reason: `scheduled` or `manual`;
- keep existing SSRF, DNS rebinding, rate, timeout, and queue protections;
- scheduler must be safe to restart.

Implementation can be a separate worker mode or a small service loop in Docker
Compose.

### 3. Historical Snapshots

Create normalized monitoring snapshots from completed scan reports.

Snapshot fields:

- monitored domain id;
- scan id;
- grade;
- score;
- certificate expiration date;
- certificate days remaining;
- supported TLS versions;
- HSTS state;
- finding codes and severities;
- created_at.

The full report remains stored as it is today. Snapshot is the compact,
query-friendly operational record.

### 4. Diff Engine

Compare the newest snapshot with the previous snapshot for the same domain.

Diff should detect:

- grade improved/degraded;
- score delta;
- certificate expiration changed;
- certificate days remaining crossed thresholds;
- added findings;
- resolved findings;
- protocol support changed;
- HSTS changed;
- new high/critical findings.

The existing report comparison logic can be reused, but monitoring diffs should
operate on snapshots rather than raw UI reports.

### 5. Event Generation

Generate durable events from snapshot diffs.

Initial event types:

- `scan_failed`;
- `grade_degraded`;
- `grade_improved`;
- `certificate_expiring`;
- `certificate_expired`;
- `critical_added`;
- `high_added`;
- `finding_resolved`;
- `legacy_tls_enabled`;
- `hsts_changed`.

Events are append-only. They are the future source for alerts, daily summaries,
and AI explanations.

## Stage 1 Non-Goals

Do not build yet:

- user registration;
- organizations and roles;
- billing;
- complex dashboard UI;
- email notification delivery;
- AI explanations;
- public status pages;
- mass import.

Stage 1 is backend/data model first.

## Minimum Verification For Stage 1

Local:

- unit tests pass;
- Python compile check passes;
- scheduler can enqueue a due monitored domain;
- completed scan creates a snapshot;
- second scan creates a diff;
- diff creates events;
- disabled domain is not scheduled;
- duplicate active scan is not enqueued.

Production smoke test after deploy:

- existing public one-shot scan still works;
- existing report page still works;
- healthcheck is green;
- one monitored test domain can be scheduled;
- snapshot and events appear in PostgreSQL;
- no unexpected queue growth.

## Pre-Deploy Backup And Rollback

Before deploying any Monitoring Core feature to the VPS, create a recovery point.

Required backup items:

- PostgreSQL dump;
- current `.env`;
- current `docker-compose.yml`;
- current deployed source tree or Git commit hash;
- current Docker image ids for `api` and `worker`;
- current Nginx config related to TLS Audit.

Recommended command sequence on VPS:

```bash
cd /opt/tls-audit
bash deploy/scripts/backup-postgres.sh
mkdir -p backups/deploy-state
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
cp .env "backups/deploy-state/.env-$STAMP"
cp docker-compose.yml "backups/deploy-state/docker-compose-$STAMP.yml"
docker compose images > "backups/deploy-state/docker-images-$STAMP.txt"
git rev-parse HEAD > "backups/deploy-state/git-revision-$STAMP.txt" 2>/dev/null || true
sudo nginx -T > "backups/deploy-state/nginx-$STAMP.conf" 2>/dev/null || true
```

Rollback principle:

- if deployment breaks public scanning, restore previous code or image first;
- then restore database only if schema/data changes caused the issue;
- keep the public scanner available even if monitoring is temporarily disabled.

## Implementation Order

1. Add database schema for monitoring registry, snapshots, and events.
2. Add shared monitoring models/repository.
3. Add API or CLI to add/list/disable monitored domains.
4. Add scheduler loop and queue integration.
5. Create snapshots after completed scans.
6. Add snapshot diff engine.
7. Generate events from diffs.
8. Add tests around scheduling, snapshots, diffs, and events.
9. Run local smoke checks.
10. Commit and push.
11. Create VPS recovery point.
12. Deploy.
13. Watch production for at least one scheduled cycle.

## Later Stages

Stage 2:

- minimal monitoring UI;
- domain history page;
- operational summary page.

Stage 3:

- alert delivery via email/webhook;
- daily/weekly digest;
- alert deduplication and severity policy.

Stage 4:

- AI-assisted summaries;
- remediation planning based on server stack;
- generated DevOps tasks.

Stage 5:

- accounts, teams, roles, and private customer workspaces if real demand exists.
