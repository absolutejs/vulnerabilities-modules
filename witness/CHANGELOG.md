# Changelog

## 0.4.4 - 2026-08-01

- Publish only full-revision witness container tags after the complete package
  gate, SPDX SBOM generation, and a high/critical vulnerability scan.
- Sign and attest digest-pinned witness images with the GitHub Actions keyless
  identity and retain immediately verified SLSA provenance and SBOM evidence.
- Pin every third-party workflow action by immutable commit and document
  digest-pinned deployment and verification instead of the mutable `main` tag.
- Use the exact Bun Alpine runtime instead of the vulnerable Debian runtime
  package set rejected by the high/critical image gate.
- Upgrade Alpine runtime packages during the image build so fixed high and
  critical vulnerabilities cannot survive because the Bun image predates the
  corresponding Alpine security update.

## 0.3.0 - 2026-07-19

- Prove checkpoint freshness without replacing immutable receipts by returning
  the authenticated subject's latest durable checkpoint in status contract v2.

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
