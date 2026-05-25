# TLS Audit Architecture (v0.2)

## Runtime Shape

```text
Browser
  |
  v
FastAPI (web + API)
  |
  +--> Redis queue + job state
  |
  +--> PostgreSQL archive
  |
  v
Scanner worker (baseline probes + testssl.sh)
  |
  v
Public target hosts only
```

Main components:

- `services/api` for public pages, API endpoints, and monitoring control flow;
- `services/worker` for active scans and report generation;
- `services/scheduler` for periodic monitoring runs;
- `shared/tls_audit/*` for domain logic (validation, scoring, monitoring, stores).

## Trust Zones

Public scan zone:

- one-off scan endpoints (`/api/check`, `/api/report/{id}`);
- no ownership requirement;
- strict target validation and abuse controls.

Private monitoring zone:

- subscription state and monitoring control endpoints;
- owner token required for access;
- `pro` weekly flow gated by ownership verification.

Internal ops zone:

- `/api/monitor/domains*` endpoints;
- admin token required (`MONITORING_ADMIN_TOKEN`);
- not intended for public browser use.

## Data Model (Operational)

Core archive:

- `scans`
- `reports`
- `findings`

Monitoring:

- `monitor_subscriptions`
- `monitored_domains`
- `monitoring_snapshots`
- `monitoring_events`
- `subscription_report_deliveries`
- `subscription_alert_deliveries`

Billing/account skeleton:

- `billing_accounts`

`monitor_subscriptions` stores ownership state for `pro`:

- `ownership_method`
- `ownership_token`
- `ownership_verified_at`

## Security Model

Target safety:

- hostname and port validation;
- deny private/loopback/link-local/metadata ranges;
- DNS resolved in API and revalidated in worker;
- mixed public/private DNS answers rejected.

Abuse protection:

- requester rate limit;
- per-target active lock + cooldown;
- queue depth guard;
- denylist controls (`BLOCKED_CLIENT_IPS`, `BLOCKED_TARGETS`).

Execution constraints:

- scanner timeouts for baseline and deep checks;
- containerized worker;
- optional host firewall egress restrictions.

Monitoring privacy:

- subscription access by signed owner token, not plain email lookup;
- `pro` requires ownership verification before recurring private reports.
