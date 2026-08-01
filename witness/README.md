# @absolutejs/vulnerabilities-witness

The witness consumes `@absolutejs/secrets@^0.9.2`, whose Agency integration is
host-owned and externalized. It never embeds a second Secrets or Agency runtime.

Independent transparency witnessing for AbsoluteJS vulnerability evidence.
The package verifies the complete signed evidence-key transparency log before
issuing an Ed25519 checkpoint receipt. Durable stores reject a lower log size
as rollback and reject two different heads observed for the same authenticated
subject and log size as equivocation.

The HTTP service has three routes:

- `POST /v1/checkpoints` authenticates a bearer token, verifies the submitted
  transparency log, and returns `{ checkpoint, registry }`.
- `GET /v1/keys` publishes the witness key registry and cross-signed rotation
  chain.
- `GET /health` returns service liveness.

```ts
import {
  EVIDENCE_WITNESS_REQUEST_CONTRACT,
  createEvidenceWitnessHttpHandler,
  createEvidenceWitnessService,
  createEvidenceWitnessSigningState,
} from "@absolutejs/vulnerabilities-witness";
import {
  createPostgresEvidenceWitnessStore,
  ensurePostgresEvidenceWitnessSchema,
} from "@absolutejs/vulnerabilities-witness/postgres";

const signingState = createEvidenceWitnessSigningState();
await ensurePostgresEvidenceWitnessSchema(sql);

const service = createEvidenceWitnessService({
  loadSigningState,
  origin: "https://witness.example",
  signingState,
  store: createPostgresEvidenceWitnessStore(sql),
  storeSigningState,
});

const fetch = createEvidenceWitnessHttpHandler({
  authenticate: async (token) => subjectsByToken.get(token) ?? null,
  service,
});

Bun.serve({ fetch, port: 3000 });
```

The signing identity contains a private key and belongs in a durable secret
broker, not PostgreSQL or source control. `service.rotate()` stores the new
secret state before activating it and publishes the cross-signed transition in
the registry. `service.maintain()` performs the same rotation only after the
configured maximum key age. In a multi-replica service, the supplied
secret-store integration must serialize rotations.

## Standalone service

The included `absolute-vulnerability-witness` executable uses PostgreSQL for
observations and accepts these deployment secrets:

- `DATABASE_URL`
- `EVIDENCE_WITNESS_ORIGIN`
- `EVIDENCE_WITNESS_SIGNING_STATE_JSON`
- `EVIDENCE_WITNESS_TOKENS_JSON`, an object mapping stable subjects to bearer
  tokens
- `EVIDENCE_WITNESS_SECRETS_PATH`, the durable encrypted secret file
- `EVIDENCE_WITNESS_SECRETS_PASSPHRASE`, the master passphrase kept outside the
  file
- `EVIDENCE_WITNESS_KEY_MAX_AGE_MS`, defaulting to 90 days
- `EVIDENCE_WITNESS_MAINTENANCE_INTERVAL_MS`, defaulting to one hour

The authenticated `GET /v1/status` endpoint reports the verified key registry
and optional backup restoration evidence. Store
`EVIDENCE_WITNESS_BACKUP_VERIFICATION_JSON` in the encrypted secret adapter
after a drill has restored both the PostgreSQL artifact and encrypted signing
state. The record must use the
`absolutejs.vulnerability-evidence-witness-backup-verification/v1` contract,
contain SHA-256 digests for both artifacts, and record both restoration times.

- `PORT`, defaulting to `3000`

The two JSON values bootstrap the encrypted file only when their entries do not
already exist. Later key rotations are written atomically to the encrypted file
before the new identity becomes active.

Run independent instances under different administrative and infrastructure
boundaries. Clients should pin each genesis witness key through an independent
channel and require a quorum with
`verifyEvidenceWitnessQuorum` from `@absolutejs/vulnerabilities`.

The repository publishes a deployable container to
`ghcr.io/absolutejs/vulnerabilities-witness`. Deploy only the digest-pinned
reference retained in the successful `witness-image-<commit>` workflow
artifact. The workflow rejects high and critical vulnerabilities, retains an
SPDX SBOM and Grype report, and immediately verifies the image's keyless
signature, SLSA provenance, and SBOM attestation against its exact GitHub
Actions identity. Never deploy the mutable `main` tag. See
[`deploy/README.md`](deploy/README.md) for the independence requirements,
bootstrap sequence, PAAS quorum configuration, and repeatable Admin drill
workflow.
