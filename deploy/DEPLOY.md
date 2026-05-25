# TLS Audit VPS Deploy (v0.2)

Актуальный путь деплоя для `v0.2` на одном VPS: Docker Compose + Nginx + Redis +
PostgreSQL.

## 1. Prepare The VPS

Install Docker, Docker Compose plugin, Nginx, and Certbot.

Open only these public ports:

- `80/tcp` for Let's Encrypt HTTP challenge and redirect;
- `443/tcp` for the public site;
- SSH from trusted addresses only.

Keep the app port bound to localhost through `API_BIND_HOST=127.0.0.1`.

The API and worker containers use explicit public DNS resolvers in
`docker-compose.yml` so target validation and scanning do not depend on stale
host resolver caches.

## 2. Configure Environment

Copy the example file and edit secrets:

```bash
cp deploy/env.example .env
```

Change at minimum:

- `PUBLIC_BASE_URL`;
- `POSTGRES_PASSWORD`;
- `DATABASE_URL`;
- `POSTGRES_DB` and `POSTGRES_USER` if you rename the database/user.

Use the same database username, password, and database name in `DATABASE_URL`.

## 3. Start The Stack

```bash
docker compose up --build -d
docker compose ps
curl -s http://127.0.0.1:8000/health
```

Expected health response:

```json
{"status":"ok","database":"enabled"}
```

`docker compose ps` should show healthy `api`, `worker`, `redis`, and `postgres`
containers after the first startup period.

If the VPS uses the old standalone Compose binary, replace `docker compose` with
`docker-compose`. The bundled maintenance scripts detect both forms.

## 4. Configure Nginx

Copy `deploy/nginx/tls-audit.conf.example` to your Nginx sites directory and
replace `tlslab.example.ru` with the real domain.

Current VPS production names:

- primary: `tlsaudit.ru`;
- canonical redirect: `www.tlsaudit.ru` -> `https://tlsaudit.ru`;
- `izis.online` is not part of the TLS Audit Nginx site.

Issue a certificate, then reload Nginx:

```bash
certbot --nginx -d tlslab.example.ru
nginx -t
systemctl reload nginx
```

## 5. Backups And Retention Cleanup

Run cleanup manually:

```bash
docker compose exec api python -m services.api.app.maintenance cleanup
```

Create a compressed Postgres backup:

```bash
bash deploy/scripts/backup-postgres.sh
```

Run backup and cleanup together:

```bash
bash deploy/scripts/run-maintenance.sh
```

Restore a backup into the current database:

```bash
bash deploy/scripts/restore-postgres.sh /opt/tls-audit/backups/tls-audit-YYYYMMDDTHHMMSSZ.sql.gz
```

Recommended systemd timer:

```bash
cp deploy/systemd/tls-audit-maintenance.service /etc/systemd/system/
cp deploy/systemd/tls-audit-maintenance.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now tls-audit-maintenance.timer
systemctl list-timers tls-audit-maintenance.timer
```

Cron alternative:

```cron
17 3 * * * cd /opt/tls-audit && bash deploy/scripts/run-maintenance.sh >/var/log/tls-audit-maintenance.log 2>&1
```

`REPORT_RETENTION_DAYS` keeps successful reports. `ERROR_RETENTION_DAYS` keeps
failed scan rows. `BACKUP_RETENTION_DAYS` controls local backup rotation.

Emergency denylist settings are read from `.env` by the API:

```bash
BLOCKED_CLIENT_IPS=203.0.113.7,198.51.100.0/24
BLOCKED_TARGETS=bad.example,*.noisy.example,bad.example:8443
docker compose up -d --force-recreate api
```

Use this for abuse control only. `BLOCKED_TARGETS` supports exact domains,
suffix masks, and optional port-specific rules.

## 6. Docker Egress Firewall

The app already validates DNS and blocks private targets in code. Add a host
firewall layer as defense in depth:

```bash
bash deploy/scripts/apply-egress-firewall.sh
```

Install the systemd service so the rules are restored after reboot:

```bash
cp deploy/systemd/tls-audit-egress-firewall.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now tls-audit-egress-firewall.service
```

The script detects `DOCKER_EGRESS_NETWORK` from `.env` (default:
`tls-audit_default`) and adds rules to the Docker `DOCKER-USER` chain. It allows
traffic inside the Compose network for Redis/Postgres/API, but rejects container
egress to private, loopback, link-local, metadata, CGNAT, benchmarking,
multicast, and reserved IPv4 ranges.

Remove only these managed rules if needed:

```bash
bash deploy/scripts/apply-egress-firewall.sh --clear
```

## 7. Monitoring And Alerts

Run the healthcheck manually:

```bash
bash deploy/scripts/check-health.sh
```

It checks:

- public homepage response;
- local `/health` response;
- Docker service health for `api`, `worker`, `redis`, and `postgres`;
- disk usage;
- TLS certificate expiry;
- Redis scan queue depth;
- latest Postgres backup age.

Install the systemd timer:

```bash
cp deploy/systemd/tls-audit-healthcheck.service /etc/systemd/system/
cp deploy/systemd/tls-audit-healthcheck.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now tls-audit-healthcheck.timer
systemctl list-timers tls-audit-healthcheck.timer
```

The last status is written to `/opt/tls-audit/logs/health-last.txt` by default.
If SMTP settings are set in `.env`, warnings and critical failures are sent by
email:

```bash
ALERT_EMAIL_TO=admin@tlsaudit.ru
ALERT_EMAIL_FROM=info@tlsaudit.ru
SMTP_URL=smtps://mail.example.ru:465
SMTP_USER=info@tlsaudit.ru
SMTP_PASSWORD=change-me
```

## 8. Privacy-Friendly Stats

TLS Audit can report aggregate server-side statistics from PostgreSQL without
browser cookies or third-party trackers:

```bash
bash deploy/scripts/report-stats.sh
bash deploy/scripts/report-stats.sh 30
```

The report includes scan totals, status counts, grade counts, common findings,
and slowest scans for the selected period. The latest report is written to
`/opt/tls-audit/logs/stats-last.json` by default.

Install the daily timer:

```bash
cp deploy/systemd/tls-audit-stats.service /etc/systemd/system/
cp deploy/systemd/tls-audit-stats.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now tls-audit-stats.timer
systemctl list-timers tls-audit-stats.timer
```

## 9. Smoke Test

```bash
curl -s -X POST http://127.0.0.1:8000/api/check \
  -H 'Content-Type: application/json' \
  -d '{"host":"example.com","port":443}'
```

Open the returned `/scan?job=...` page through the public domain and verify that
progress and report rendering work.

Additional v0.2 checks:

- create free monitoring subscription and confirm by email token;
- create pro subscription and verify ownership challenge endpoints;
- trigger `run-now` and confirm report email delivery;
- confirm no duplicate weekly delivery for the same scan.

## 10. Before Public Announcement

- keep `tlsaudit.ru` as the canonical domain and verify redirects after Nginx edits;
- make sure `admin@tlsaudit.ru` or equivalent aliases deliver mail;
- confirm `tls-audit-egress-firewall.service` is active;
- set backups for the Postgres Docker volume;
- verify `tls-audit-maintenance.timer`, `tls-audit-healthcheck.timer`, and
  `tls-audit-stats.timer`.
