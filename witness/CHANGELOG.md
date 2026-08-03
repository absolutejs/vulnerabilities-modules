# Changelog

## 0.7.2 - 2026-08-03

- Use a Bash-compatible integer literal for the host backup-verification
  record size guard, preserving the defense-in-depth rejection before any
  witness container is stopped.

## 0.7.1 - 2026-08-03

- Accept systemd's intentionally read-only `0400` materialization for the
  encrypted backup-writer credential while continuing to require the separate
  non-secret backup configuration to be root-owned `0600`.
- Exercise the backup uploader with the actual `LoadCredentialEncrypted=` file
  mode so package tests match the deployed systemd boundary.

## 0.6.0 - 2026-08-03

- Add runtime-only backup creation and disposable no-egress restore
  verification for PostgreSQL observations and encrypted signing state.
- Add a bounded backup CLI that derives the public key registry from a restored
  encrypted state file and records validated restore evidence without exposing
  secret material.

## 0.5.2 - 2026-08-03

- Read systemd's generated `CREDENTIALS_DIRECTORY` inside the runtime
  materializer process so encrypted credentials are found on deployed hosts,
  while preserving the explicit-directory interface for existing callers.
- Wait for the configured PostgreSQL database to accept a real query before
  exercising the persistence canary, removing an initialization race.

## 0.5.1 - 2026-08-03

- Pass systemd's exported `CREDENTIALS_DIRECTORY` to the runtime materializer;
  `%d` is supported in environment assignments but remains literal in service
  command arguments on the deployed systemd version.

## 0.5.0 - 2026-08-03

- Add optional systemd host-bound encrypted credentials that atomically
  recreate runtime-only witness and TLS files after reboot, fail closed on a
  partial credential set, and remove materialized plaintext after shutdown.
- Document the non-TPM residual risk and require independent host keys and
  credential sets across quorum members.

## 0.4.8 - 2026-08-03

- Safely migrate an existing encrypted witness-state file from the legacy host
  UID to the dedicated runtime identity and reject symbolic-link state paths.
- Exercise that ownership migration against a disposable named volume in the
  release pipeline.

## 0.4.7 - 2026-08-03

- Run the single-host witness under dedicated numeric UID/GID `65532:65532`
  instead of a common host-login identity.
- Require root-owned execute-only TLS path directories so the witness can read
  its private key without granting directory listing or host-login ownership.

## 0.4.6 - 2026-08-03

- Mount the PostgreSQL 18 persistent volume at its supported major-version
  root and verify that a synthetic canary survives a disposable container
  restart.

## 0.4.5 - 2026-08-02

- Add a reusable digest-pinned single-host deployment contract with native
  TLS, runtime-only secret injection, private PostgreSQL, and explicit
  metadata/private-network egress denial.
- Refresh the exact PostgreSQL support-image digest after the release scan
  identified vulnerable Go standard-library components in the prior image.
- Pin the current verified Grype release for both image gates instead of
  inheriting the scan action's older bundled scanner.

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
- Identify the active `absolutejs/vulnerabilities-modules` repository through
  the standard OCI source annotation instead of the archived standalone
  witness repository.

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
