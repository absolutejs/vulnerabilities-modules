# Changelog

## 0.2.1 - 2026-07-19

- Persist an optional initial backup-verification record from the standalone
  service environment into its encrypted secret adapter.

## 0.2.0 - 2026-07-19

- Add an authenticated operational-status endpoint with the verified witness
  key registry and concrete database/signing-state backup restore evidence.
- Treat missing or malformed backup verification as unavailable posture rather
  than inferring recoverability from service liveness.

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
