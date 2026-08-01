# Independent witness deployment contract

Deploy at least two instances from the exact
`ghcr.io/absolutejs/vulnerabilities-witness@sha256:<digest>` reference retained
as `image-reference.txt` in the successful `witness-image-<commit>` workflow
artifact. Before provisioning, verify that digest's keyless signature, SLSA
provenance, and SPDX SBOM attestation with `@absolutejs/attest` against the
exact repository, workflow, ref, and commit that produced it. Mutable tags,
including `main`, are not deployment inputs. A production quorum is independent
only when each instance has all of the following:

- a different administrative account or organization;
- a different PostgreSQL database and database credential;
- a different runtime identity and secret-store passphrase;
- an independently generated witness signing state and bearer token;
- a different HTTPS origin and failure domain.

Do not copy a witness database, encrypted secret file, signing state, token, or
passphrase between instances. Sharing any of these collapses the intended trust
boundary even if the containers run in different regions.

Each deployment needs a durable writable volume for
`EVIDENCE_WITNESS_SECRETS_PATH`. The passphrase must be injected by the hosting
provider's secret manager and must not be stored on that volume. Provide
`EVIDENCE_WITNESS_SIGNING_STATE_JSON` and `EVIDENCE_WITNESS_TOKENS_JSON` only
for first boot; the service encrypts them into the file and subsequently loads
the durable copy. Back up the encrypted file and PostgreSQL independently.

After each service is live:

1. Check `GET /health` and retrieve `GET /v1/keys` over HTTPS.
2. Transfer the genesis public key fingerprint through an independent channel.
3. Configure PAAS `VULNERABILITY_EVIDENCE_WITNESSES_JSON` with a unique ID,
   HTTPS checkpoint URL, and pinned genesis public key for each service.
4. Store the corresponding ID-to-token map as the brokered
   `VULNERABILITY_EVIDENCE_WITNESS_TOKENS_JSON` secret.
5. Set `VULNERABILITY_EVIDENCE_WITNESS_QUORUM` to the required number of
   distinct witnesses.
6. Run `resilience.evidence-witness-live-quorum` from the PAAS Admin drills
   panel. Its retained run shows the observed head, size, origins, fingerprints,
   replay result, and satisfied quorum.

Use `adversarial.evidence-witness-integrity` for repeatable rollback,
equivocation, fork, and key-rotation attacks. Those mutations intentionally run
against disposable local stores so a real witness subject is never poisoned by
a drill.
