# Roadmap

## Phase 0 - Product Shape

Goal: prove that the service is useful before building the full laboratory.

Deliverables:

- one public hostname input, default port 443;
- Russian report page with grade, certificate summary, TLS versions, HTTP header notes;
- explicit disclaimer that the MVP grade is not an SSL Labs-compatible rating;
- private result URL by default, optional public sharing later.

Key references:

- SSL Labs server test and rating guide: https://www.ssllabs.com/ssltest/ and https://www.ssllabs.com/projects/rating-guide/
- OWASP TLS Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html
- MDN TLS configuration guide: https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/TLS
- testssl.sh project: https://github.com/testssl/testssl.sh

## Phase 1 - MVP Scanner

Checks:

- DNS resolution with private/reserved network blocking;
- certificate validity, hostname match, issuer, SAN, expiration;
- certificate chain extraction where possible;
- TLS 1.0, 1.1, 1.2, 1.3 handshake probes;
- negotiated cipher per supported TLS version;
- HSTS presence and basic strength;
- simple public grade from A+ to D.

Tech:

- Python scanner core;
- sync local web UI for early demos;
- JSON result format stable enough to store.

## Phase 2 - Real Web Service

Components:

- API service: FastAPI or similar;
- worker queue: Redis + RQ/Celery/Arq;
- database: PostgreSQL;
- scanner workers running in locked-down containers;
- reverse proxy: Nginx/Caddy;
- observability: structured logs, metrics, scan duration/error tracking.

Features:

- asynchronous scans;
- queue position and progress;
- result pages;
- scan history for logged-in users;
- per-IP and per-domain rate limits;
- admin abuse controls.

## Phase 3 - Deep TLS Analysis

Checks:

- full cipher suite enumeration by protocol;
- key exchange strength;
- forward secrecy;
- server cipher preference;
- OCSP stapling and revocation where reliable;
- CAA, CT/SCT visibility;
- weak algorithms: RC4, 3DES/SWEET32, CBC-only configs, NULL/EXPORT/anonymous suites;
- compression and renegotiation issues;
- vulnerability probes such as Heartbleed/ROBOT only after sandboxing and legal review.

Implementation options:

- embed a native scanner library where possible;
- run `testssl.sh` in a container worker and parse JSON output;
- keep our own normalized finding model and grading policy.

## Phase 4 - Grading Policy

Build a transparent Russian grading guide.

Principles:

- do not claim SSL Labs equivalence until methodology is validated;
- keep an internal scoring guide and expose only clear user-facing reasons in reports;
- separate certificate trust failures from configuration weaknesses;
- include remediation examples for Nginx, Apache, HAProxy, Caddy, and common CDN panels;
- version the grading policy, because TLS recommendations change.

Initial rough grade semantics:

- `A+`: valid certificate, TLS 1.3 and 1.2, no legacy TLS, strong HSTS;
- `A`: strong modern configuration with minor hardening gaps;
- `B`: acceptable but has legacy compatibility or missing hardening;
- `C/D`: weak protocols, weak algorithms, or incomplete deployment;
- `D`: worst public grade for broken TLS, severe cryptographic weakness,
  certificate trust failure, hostname mismatch, or no usable secure endpoint.

## Phase 5 - Public Launch

Before public traffic:

- domain and branding;
- abuse policy and robots guidance;
- privacy policy;
- Terms of Use for scanning only systems the user owns or is authorized to test;
- capacity limits for the VPS;
- backups and monitoring;
- responsible disclosure contact.

## Phase 6 - Differentiation For RU Market

Ideas:

- Russian-language remediation text;
- presets for Russian hosting panels and popular VPS stacks;
- exportable PDF report for clients;
- API for CI/CD checks;
- checks for common misconfigurations in `.ru`, `.рф`, corporate, and government-facing deployments;
- public education pages with current TLS baseline examples.
