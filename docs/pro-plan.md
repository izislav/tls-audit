# TLS Audit Pro

This document fixes the product definition of the paid `Pro` tier.

## Positioning

`Pro` is not a donation and not a symbolic "support project" label.
`Pro` is a paid operational tier for users who need continuous monitoring,
change visibility, and actionable alerts across multiple domains.

## Price

- `$10 / month`
- up to `10` domains per email

## Free vs Pro

### Free

- `1` domain per email
- regular email report
- simple monitoring flow
- no paid-only alert pack

### Pro

- up to `10` domains per email
- expanded email report
- change tracking between scans
- alert flow for important regressions
- domain list with statuses
- manual run-now action
- higher-value monitoring workflow intended for ongoing operational use

## Pro Features

The minimum practical Pro feature set is:

1. domain list for the owner email;
2. per-domain status and last/next activity;
3. run-now action;
4. diff against previous scan;
5. alert on grade degradation;
6. alert on certificate expiry window;
7. alert on newly added critical findings;
8. expanded email report;
9. trend/history view;
10. monthly billing lifecycle.

## Delivery Order

1. domain list and ownership flow;
2. alert rules;
3. trend/history UI;
4. billing provider integration;
5. production rollout.

## Current State

Already present:

- `free` vs `Pro` split in product language;
- `Pro` billing/account lifecycle skeleton;
- `Pro` gating for support-plan subscriptions;
- expanded `Pro` email format;
- `run-now` for subscriptions.

Missing before production billing:

- visible domain list for `Pro`;
- real alert pack;
- real payment provider;
- webhook-driven activation/cancel flow.
