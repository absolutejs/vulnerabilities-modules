# Changelog

## 0.1.1 - 2026-07-19

- Persist standalone-service signing state and subject tokens through the
  AbsoluteJS AES-256-GCM encrypted-file secret adapter.
- Schedule age-based witness-key rotation and durably store the cross-signed
  state before activating the replacement key.

## 0.1.0 - 2026-07-19

- Verify complete signed evidence transparency logs before witnessing.
- Persist authenticated-subject observations through memory and PostgreSQL
  stores with atomic rollback and equivocation rejection.
- Publish cross-signed witness key registries and rotate signing identities.
- Provide a bearer-authenticated Fetch handler and standalone Bun service.
