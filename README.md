# TLS Audit

TLS Audit is a Russian-language HTTPS/TLS diagnostics service.
It scans a public hostname and builds a report with:

- public grade (`A+` to `D`);
- findings grouped by risk;
- actionable configuration recommendations;
- provenance/evidence for scanner conclusions.

The service does not claim one-to-one SSL Labs equivalence.
Current methodology version is `0.2`; current service release is `0.2.1`.

## Current Product State

Implemented:

- FastAPI web/API service;
- Redis-backed async scan queue;
- PostgreSQL archive for scans/reports/findings;
- scanner worker with baseline Python probes and `testssl.sh`;
- report provenance block (scanner sources, versions, scan metadata);
- monitoring subscriptions (`free` and `pro` flow);
- private subscription management by signed, expiring owner token;
- ownership verification flow for `pro` subscriptions (DNS TXT or HTTP file challenge);
- Russian TLS/GOCT compatibility block separated from global grade.

Security controls:

- SSRF and DNS rebinding protection with connections pinned to validated IP addresses;
- private/local/service targets blocked;
- separate scan, monitoring, and email rate limits plus queue depth guard;
- per-target active lock and cooldown;
- scanner time limits.
- production containers run read-only as a non-root user;
- readiness checks cover PostgreSQL, Redis, worker, and scheduler.

## Local Run

Start stack:

```bash
docker-compose up --build -d
curl -s http://127.0.0.1:8000/health/ready
```

Open:

```text
http://127.0.0.1:8000/
```

Run tests:

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
```

Maintenance commands:

```bash
docker-compose exec api python -m services.api.app.maintenance cleanup
bash deploy/scripts/backup-postgres.sh
```

## Core API

Public scan:

- `POST /api/check` with `{"host":"example.ru","port":443}`
- `GET /api/check/{id}`
- `GET /api/report/{id}`
- `GET /api/report/{id}/compare`

Monitoring subscriptions:

- `POST /api/subscriptions/monitoring`
- `GET /api/subscriptions/monitoring?token=...`
- `GET /api/subscriptions/monitoring/events?token=...`
- `POST /api/subscriptions/monitoring/{id}/run-now?token=...`
- `POST /api/subscriptions/monitoring/{id}/ownership/challenge?token=...`
- `POST /api/subscriptions/monitoring/{id}/ownership/verify?token=...`

## Documentation

- Deploy: [DEPLOY.md](deploy/DEPLOY.md)
- Work plan `0.2`: [work-plan.md](docs/work-plan.md)
- Roadmap: [roadmap.md](docs/roadmap.md)
- Current state: [v0.2-status.md](docs/v0.2-status.md)
