# TLS Audit

TLS Audit is a free Russian-language HTTPS/TLS assessment service inspired by
SSL Labs. It accepts a public hostname, scans certificate/TLS/server settings,
and produces a readable Russian report with a public grade from `A+` to `D`.

The current MVP includes:

- FastAPI web/API service;
- Redis-backed job queue and scan state;
- PostgreSQL archive for scan/report/finding data;
- worker scanner with baseline Python probes and `testssl.sh`;
- SSRF/DNS rebinding protections;
- Russian recommendations and config snippets;
- Russian TLS/ГОСТ compatibility block;
- public rate limits, per-target scan lock, queue guard, and retention cleanup.

## Local Docker Run

```bash
docker compose up --build -d
curl -s http://127.0.0.1:8000/health
```

Open:

```text
http://127.0.0.1:8000/
```

Run tests:

```bash
python3 -m unittest discover -s tests
```

Cleanup archived reports:

```bash
docker compose exec api python -m services.api.app.maintenance cleanup
```

Backup Postgres:

```bash
bash deploy/scripts/backup-postgres.sh
```

## API

- `POST /api/check` with `{"host":"example.ru","port":443}`
- `GET /api/check/{id}`
- `GET /api/report/{id}`

## Deployment

See [deploy/DEPLOY.md](deploy/DEPLOY.md).

## Safety Rules

The service is designed to scan only public Internet hosts by default. It rejects
localhost/private/link-local/reserved/metadata addresses, revalidates DNS in the
worker, rate-limits requesters, blocks parallel scans for the same target, and
uses scanner timeouts.

The MVP is not a claim of SSL Labs equivalence. The scoring policy is local and
can be revised later without changing the scanner architecture.
