# TLS Audit Work Plan

This file tracks the sequential plan from proof-of-concept to production MVP.

## Completed

1. Local proof-of-concept scanner and UI.
2. Basic Russian report with grades and recommendations.
3. In-memory scan queue with progress and timeout.
4. Result deletion and no-store HTTP responses.
5. Production MVP skeleton:
   - shared report/scoring/validation models;
   - FastAPI API skeleton;
   - worker skeleton;
   - Redis job format;
   - Docker Compose for API, worker, Redis, PostgreSQL;
   - Russian trust-list placeholder and documentation.
6. Shared Redis-backed job lifecycle:
   - API creates job;
   - worker updates progress;
   - worker stores report into the same job record.
7. PostgreSQL archive layer:
   - schema for scans, reports, and findings;
   - API archives scan creation;
   - worker saves final report JSON and normalized findings;
   - `/api/check/{id}` and `/api/report/{id}` can read durable records.
8. Production report UI v1:
   - `/` and `/scan?job=...` render the same application;
   - scan form creates jobs through the API;
   - progress polling is visible;
   - completed reports show grade, summary, findings, recommendations,
     certificate, TLS protocols, cipher probes, HSTS, Russian compatibility,
     and raw JSON.
9. First `testssl.sh` integration:
   - worker image installs Debian `testssl.sh`;
   - worker runs `testssl` after the baseline scanner with timeout settings;
   - raw structured JSON is stored under `report.raw.testssl`;
   - parser imports protocols, vulnerabilities, OCSP-related rows, and cipher tests;
   - UI shows vulnerabilities, OCSP/stapling data, and testssl cipher tests;
   - scoring groups repeated findings from the same problem class.
10. Concrete testssl recommendations and parser expansion:
   - BREACH, LUCKY13/CBC, and OCSP stapling have dedicated Russian remediation;
   - parser imports chain/trust rows without huge PEM blocks;
   - parser imports server preference and forward secrecy/DH/EC rows;
   - OCSP stapling `not offered` becomes an informational finding;
   - UI shows chain/trust and extra cipher/forward-secrecy data.
11. Russian TLS/GOST compatibility block:
   - issuer/root matching against updateable JSON trust data;
   - ГОСТ OID/keyword detection in certificate, chain, and TLS rows;
   - separate status, summary, and recommendations that do not affect A-F grade;
   - worker/API images copy `data/russian_trust` for container scans.
12. Production hardening v1:
   - API stores initially resolved public addresses in queued jobs;
   - worker repeats DNS/public-IP validation before scanning;
   - worker rejects jobs when DNS answers no longer overlap with queued addresses;
   - service/local hostnames and dangerous service ports are blocked;
   - mixed public/private DNS answers are rejected instead of partially accepted.
13. Public grading scale cleanup:
   - public grades are capped at `D`; no `F` or `T` is shown;
   - legacy `F`/`T` grade caps are normalized to `D`;
   - public `D` reports use a visible score floor instead of showing `0 / 100`;
   - raw internal score is kept under `raw.scoring.raw_score` for diagnostics.
14. Production hardening v2:
   - Redis-backed API rate limit with in-memory fallback for local tests;
   - CAPTCHA-ready threshold metadata after repeated requests;
   - per-target active scan lock and short cooldown after completion;
   - queue depth guard before accepting new jobs;
   - structured JSON events for queued, rejected, started, done, and failed scans;
   - `testssl.sh` timeout follows scanner limits and terminates child processes.
15. VPS deploy preparation:
   - environment template for production secrets and limits;
   - Nginx reverse-proxy example;
   - report retention cleanup command;
   - Postgres backup/restore scripts;
   - systemd timer example for backup and cleanup;
   - healthchecks and restart policies in Docker Compose;
   - deployment checklist for one-VPS Docker Compose launch.
16. Scoring policy calibration v2:
   - worst public grade remains `D`, with an internal raw score kept for diagnostics;
   - BREACH, LUCKY13 with modern TLS, OCSP stapling, and HSTS preload are shown as
     context/hardening instead of hard grade caps;
   - cipher findings are split into dangerous, RC4, 3DES, CBC-only, and accepted CBC;
   - accepted CBC caps at `B`, while dangerous cipher classes can still cap at `D`;
   - report UI separates critical risks, security impact, configuration improvements,
     and informational notices.
17. Production domain binding:
   - `tlsaudit.ru` and `www.tlsaudit.ru` point to the VPS;
   - separate Let's Encrypt certificate issued for the new domain;
   - Nginx serves `tlsaudit.ru` as canonical;
   - `www.tlsaudit.ru` redirects to `https://tlsaudit.ru`;
   - `izis.online` is removed from the TLS Audit Nginx site.
18. Public SEO baseline:
   - canonical URL, meta description, Open Graph/Twitter metadata, and JSON-LD;
   - `robots.txt` and `sitemap.xml` generated from `PUBLIC_BASE_URL`;
   - `/about` redirected back to the main page after moving the service
     explanation into the landing page.
19. Public trust pages v1:
   - privacy policy, terms of use, cookie policy, and security/acceptable-use
     pages;
   - public contact email `admin@tlsaudit.ru`;
   - footer links from the main UI;
   - legal/growth follow-up plan recorded in `docs/growth-plan.md`.
20. Monitoring and backup foundation:
   - healthcheck script for public URL, local health, Docker services, disk,
     certificate expiry, queue depth, and backup freshness;
   - systemd timer for the healthcheck;
   - daily maintenance timer covers Postgres backup and retention cleanup.
21. Abuse control foundation:
   - configurable `BLOCKED_CLIENT_IPS` for exact IP/CIDR requester blocking;
   - configurable `BLOCKED_TARGETS` for exact, suffix, and port-specific target
     blocking;
   - API rejects denylisted requesters/targets before queueing scans.
22. Docker egress firewall foundation:
   - host-level `DOCKER-USER` rules block container egress to private, loopback,
     link-local, metadata, CGNAT, multicast, and reserved IPv4 ranges;
   - Compose-network internal traffic remains allowed for Redis/Postgres/API;
   - systemd service reapplies rules after Docker starts.
23. SEO content foundation:
   - first landing pages for SSL certificate checks, TLS 1.2/1.3 checks, and
     HSTS/A+ intent;
   - first configuration pages for Nginx, Apache, Caddy, and HAProxy;
   - sitemap includes landing pages automatically through `STATIC_PAGES`;
   - footer links expose the pages to users and crawlers.
24. Privacy-friendly stats foundation:
   - maintenance `stats` command summarizes scans from PostgreSQL;
   - `report-stats.sh` writes aggregate JSON without browser cookies or
     third-party analytics;
   - daily systemd timer can refresh `/opt/tls-audit/logs/stats-last.json`.

## Current Stage

Live MVP deployed on the VPS; continue public-launch hardening and demand
generation from `docs/growth-plan.md`.

## Next Stages

1. Make sure `admin@tlsaudit.ru` or equivalent aliases deliver mail.
2. Connect real SMTP credentials for email alerts.
3. Continue production hardening:
   - CAPTCHA provider integration;
4. Add optional PDF export.
5. Add monitoring/notifications for certificate expiry.

## Deferred

- user accounts;
- paid plans;
- mass scanning;
- public domain rankings without consent.
