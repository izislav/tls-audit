# TLS Audit: Production Reliability and Growth Checklist

This checklist is the working list for two tracks that can be done now:

1. production reliability;
2. growth and indexing.

Use it before each public release and after every significant VPS change.

## 1. Production Reliability

1. Run unit tests before deployment.
2. Keep a fresh PostgreSQL backup before every release.
3. Verify restore from a backup at least on a schedule.
4. Check disk usage, Docker image growth, and log retention on the VPS.
5. Keep `api`, `worker`, `scheduler`, `redis`, and `postgres` healthy after deploy.

## 2. Growth and Indexing

6. Keep `robots.txt`, `sitemap.xml`, canonical URLs, and verification tags in sync.
7. Maintain page titles and descriptions for the main topic pages.
8. Keep structured data (`schema.org`) on the pages that need search visibility.
9. Keep the main landing page concise, with clear product positioning and scan counters.
10. Make internal links point to the public pages that answer real search intent.

## What this does not cover

- billing implementation;
- PDF exports;
- social growth;
- backlink campaigns;
- advanced account management.

## Recommended order

1. Reliability first.
2. Indexing and content second.
3. Measure demand after both are stable.

