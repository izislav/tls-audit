# Architecture

## MVP

The current MVP keeps everything in one process so the first version is easy to
understand:

```text
Browser/CLI -> tls_guard.scanner -> target HTTPS server
```

This is fine for local development, but not safe enough for public Internet use.

## Production Shape

```text
Browser
  |
  v
Web/API service
  |
  v
Job queue
  |
  v
Isolated scanner workers
  |
  v
Public target hosts

Database stores scan metadata and normalized results.
Object storage can hold raw scanner JSON artifacts.
```

## Boundaries

Web/API service:

- validates input;
- rejects private and reserved targets;
- creates scan jobs;
- returns progress and reports;
- never runs active scanner probes directly.

Scanner worker:

- runs with low privileges;
- has no access to cloud metadata endpoints or internal networks;
- uses hard timeouts;
- produces normalized JSON;
- can run heavier tools such as `testssl.sh` inside a container.

Database:

- stores target, timestamps, grade, findings, and raw result pointers;
- avoids publishing hostnames/results unless the user asks to share them;
- supports expiration/deletion policies.

## Security Controls

Input validation:

- accept hostname plus optional port;
- reject schemes, paths, credentials, wildcards, and control characters;
- resolve DNS server-side;
- block private, loopback, link-local, multicast, reserved, and metadata ranges;
- re-check resolved IPs inside the worker immediately before connecting.

Abuse controls:

- rate limits by requester IP, target host, and target IP/ASN;
- per-scan connection and time limits;
- queue concurrency caps;
- denylist for sensitive networks;
- audit log for abuse investigations.

Deployment:

- run scanner workers in containers or separate VMs;
- deny outbound access to internal ranges at firewall level;
- keep OpenSSL and scanner tools updated;
- expose only the web/API port publicly.

