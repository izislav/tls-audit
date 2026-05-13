# Production MVP Plan

The current service is the production-MVP base. It uses the `tls_guard` package
as the baseline scanner and adds API, queue, worker, parser, scoring, database,
and deployment layers around it.

```text
Frontend -> FastAPI API -> Redis Queue -> Scanner Worker -> Parser/Scoring -> PostgreSQL -> UI/API
```

## Implemented MVP Base

- `shared/tls_audit`: report models, validation, scoring, recommendations;
- `services/api`: FastAPI endpoints, frontend, rate limits, target admission;
- `services/worker`: scanner worker, baseline probes, `testssl.sh` integration;
- `docker-compose.yml`: API, worker, Redis, PostgreSQL;
- `data/russian_trust`: placeholder for updateable Russian trust data;
- `deploy/postgres/schema.sql`: durable scan/report/finding storage schema.
- `deploy/DEPLOY.md`: first VPS deployment path.

The API already exposes:

- `POST /api/check`
- `GET /api/check/{id}`
- `GET /api/report/{id}`

The API and worker now share a Redis-backed job record format:

- API creates `tls-audit:job:{id}` and pushes the job id/payload into the queue;
- worker marks the job as `running`, updates progress, then stores the final report
  back into the same job record;
- `GET /api/check/{id}` reads status/progress from the shared job record;
- `GET /api/report/{id}` returns the report when status is `done`.

When Redis is not configured, the API uses an in-memory store and a local file
queue fallback. That mode is only for smoke development because a separate worker
process cannot update the API's memory.

PostgreSQL is now an archive layer:

- Redis remains responsible for queue and current status.
- PostgreSQL stores durable scan rows, final report JSON, raw scanner JSON, and
  extracted findings.
- Local development can omit `DATABASE_URL`; Docker Compose provides it.
- The bundled Postgres service mounts `deploy/postgres/schema.sql` at startup.
- Old reports can be removed with
  `python -m services.api.app.maintenance cleanup`.

Public MVP hardening now includes:

- SSRF and DNS rebinding checks in API and worker;
- Redis-backed requester rate limit;
- per-target active scan lock and short cooldown;
- queue depth guard;
- structured JSON scan events;
- scanner and `testssl.sh` timeouts.

The current grading policy intentionally separates hard TLS failures from hardening:

- public grades stop at `D`; legacy `F`/`T` caps are normalized to `D`;
- RC4, NULL, EXPORT, anonymous suites, SSLv2/SSLv3, certificate failures, and no TLS
  remain hard blockers;
- accepted CBC suites are treated as legacy compatibility and cap at `B`, not `C`;
- BREACH, OCSP stapling, HSTS preload, and modern-TLS LUCKY13 reminders stay visible
  without acting as critical TLS failures.

## Next Engineering Steps

1. Add privacy/abuse pages before public announcement.
2. Add backups and log/disk monitoring dashboards.
3. Add admin denylist and CAPTCHA provider integration.
4. Revisit scoring policy after scanning a set of real Russian sites.
