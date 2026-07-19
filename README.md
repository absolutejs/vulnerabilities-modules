# @absolutejs/vulnerabilities-witness

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
- `PORT`, defaulting to `3000`

The two JSON values bootstrap the encrypted file only when their entries do not
already exist. Later key rotations are written atomically to the encrypted file
before the new identity becomes active.

Run independent instances under different administrative and infrastructure
boundaries. Clients should pin each genesis witness key through an independent
channel and require a quorum with
`verifyEvidenceWitnessQuorum` from `@absolutejs/vulnerabilities`.
