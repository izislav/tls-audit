# TLS Audit Work Plan

Version: `0.2`

This file tracks the main product plan after the first public MVP. Version
`0.2` means the roadmap is organized around three stages:

1. become a trustworthy public diagnostic tool;
2. turn `Pro` into a real private monitoring product;
3. differentiate from SSL Labs with Russian-language operational value.

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

Live MVP deployed on the VPS. The current task is to move from "working MVP" to
"publicly trustworthy tool" before adding more surface area.

## Plan 0.2

### Stage 1 - Public Trust

Goal: users should understand why the report can be trusted, what it checks,
and where its limits are.

Deliverables:

1. public methodology page;
2. comparison page: `TLS Audit vs SSL Labs`;
3. clear disclaimer: not a replacement for SSL Labs, but a Russian-language
   diagnostic assistant;
4. evidence blocks in reports;
5. scanner versions in reports;
6. methodology changelog;
7. sample reports;
8. saved public report links;
9. public report links that can be shared safely.

Details:

- methodology must explain what is checked, how it affects the public grade,
  why it matters, what reference backs it, how to fix it, and what is not
  checked;
- evidence must show which facts came from the baseline Python scanner,
  `testssl.sh`, OpenSSL, HTTP header probes, and DNS probes;
- reports should stay readable, but important conclusions must be inspectable
  by source, timestamp, scanner version, and short raw snippet.

### Stage 2 - Pro As Product

Goal: `Pro` must stop being a button and become a private monitoring product
with clear ownership and predictable value.

Minimum `Pro` scope:

1. email confirmation;
2. ownership verification by DNS TXT or HTTP file;
3. `1-10` domains per owner;
4. weekly report;
5. alerts on grade drop, certificate expiry, and TLS/config changes;
6. diff between checks;
7. CSV/JSON export.

Rules:

- public scan and private monitoring are different trust zones;
- private monitoring must be tied to verified owner identity;
- expanded recurring security reports must not be sent without ownership
  verification;
- monitoring endpoints must not remain openly callable.

### Stage 3 - Differentiation

Goal: win not by copying SSL Labs, but by being more useful for Russian-speaking
operators and teams.

Unique value:

1. Russian explanations of what is broken and how to fix it;
2. ready configs for Nginx, Apache, Caddy, and HAProxy;
3. separate GOST / Russian CA compatibility block;
4. monitoring of changes over time;
5. "what changed after the fix" view;
6. executive report for owners plus technical report for admins;
7. API/webhook surface for agencies and hosting providers.

## Priority Roadmap

### Urgent

1. close monitoring API behind ownership-controlled access;
2. add email confirmation;
3. add ownership verification for `Pro` domains;
4. make grading methodology transparent;
5. add raw evidence and scanner versions.

### Then

1. decide whether to keep Python-generated frontend or move to
   `Jinja + static JS` / `React`;
2. add accounts if signed-email ownership stops being enough;
3. add billing provider integration;
4. add dashboard;
5. add webhook/email alert pack;
6. compare recommendations against Mozilla recommended configurations.

## Working Interpretation

Version `0.2` means feature growth is no longer the default priority. Trust,
explainability, ownership, and product boundaries come first.

## Deferred

- user accounts;
- paid plans;
- mass scanning;
- public domain rankings without consent.
