# Changelog

## 0.2.0 - 2026-07-18

- Add a live inventory provider contract that reloads deployment inventory on
  every worker run without requiring a restart.
- Track inventory provenance and added, changed, and removed deployment drift
  through metrics and lifecycle events.
- Preserve immutable inventory evidence during correlation and reconcile
  findings from deployments removed between snapshots.

## 0.1.0 - 2026-07-18

- Add continuous EPSS, KEV, OSV, and Ubuntu feed refresh with durable history,
  distributed leases, bounded retries, and overlap coalescing.
- Add inventory correlation, VEX reconciliation, risk assessment, remediation
  drafting and verification, stage events, health, and scheduler metrics.
- Add memory and PostgreSQL persistence assembly helpers.
