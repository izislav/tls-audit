# Production MVP Baseline (Current)

This document captures what is already in production baseline after the merge to
`main`.

## Core Stack

```text
Frontend -> FastAPI API -> Redis Queue -> Worker -> Parser/Scoring -> PostgreSQL -> UI/API
```

Services:

- `api`
- `worker`
- `scheduler`
- `redis`
- `postgres`

## Implemented Product Baseline

Public diagnostics:

- one-off public scans;
- grade `A+...D` with grouped findings and recommendations;
- methodology pages and trust disclaimers;
- comparison endpoint (`/api/report/{id}/compare`);
- evidence/provenance block in report UI.

Monitoring:

- `free` and `pro` subscription flow;
- email confirmation;
- owner-token access to private monitoring state;
- run-now action per subscription;
- recurring reports with duplicate-delivery protection.

`pro` ownership:

- challenge creation (`dns_txt` or `http_file`);
- verification endpoint;
- support-plan recurring flow requires ownership verification.

Security:

- SSRF + DNS rebinding protections;
- public/private target blocking;
- rate limit, target lock, queue guard;
- scanner timeouts;
- optional host-level Docker egress firewall.

## Operational Baseline

- PostgreSQL schema includes scan archive, monitoring history, and billing skeleton.
- Daily maintenance and backup scripts are available under `deploy/scripts`.
- Healthcheck and stats scripts are available for timer-based operations.

## Known Product Boundaries

- No full account system yet.
- Billing provider is still a skeleton flow.
- Ownership verification is present but still maturing operationally.
- Methodology is versioned and intentionally not advertised as SSL Labs equivalent.
