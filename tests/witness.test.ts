import {
  createEvidenceSigningIdentity,
  createEvidenceSigningKeyTransition,
  evidenceVerificationKeyFrom,
} from "@absolutejs/vulnerabilities/evidence-bundle";
import {
  appendEvidenceKeyRotation,
  createEvidenceKeyTransparencyLog,
} from "@absolutejs/vulnerabilities/evidence-transparency";
import { describe, expect, test } from "bun:test";
import {
  EVIDENCE_WITNESS_REQUEST_CONTRACT,
  EvidenceWitnessEquivocationError,
  EvidenceWitnessRollbackError,
  createEvidenceWitnessHttpHandler,
  createEvidenceWitnessService,
  createEvidenceWitnessSigningState,
  createMemoryEvidenceWitnessStore,
  encodeEvidenceWitnessSigningState,
  evidenceWitnessKeyRegistryFrom,
  rotateEvidenceWitnessSigningState,
  verifyEvidenceWitnessKeyRegistry,
} from "../src";

const serviceFixture = () => {
  const signingState = createEvidenceWitnessSigningState(
    "2026-07-19T00:00:00Z",
  );
  let encoded = encodeEvidenceWitnessSigningState(signingState);
  const store = createMemoryEvidenceWitnessStore();
  const service = createEvidenceWitnessService({
    loadSigningState: async () => encoded,
    origin: "https://witness.example",
    signingState,
    store,
    storeSigningState: async (next) => {
      encoded = next;
    },
  });

  return { service, signingState, store };
};

describe("evidence witness service", () => {
  test("cross-signs witness key rotation back to a pinned genesis key", async () => {
    const state = createEvidenceWitnessSigningState("2026-07-19T00:00:00Z");
    const rotated = rotateEvidenceWitnessSigningState(
      state,
      "2026-07-20T00:00:00Z",
    );
    const registry = evidenceWitnessKeyRegistryFrom(rotated);
    const verification = verifyEvidenceWitnessKeyRegistry({
      registry,
      trustedKeys: [evidenceVerificationKeyFrom(state.identity)],
    });

    expect(verification.trust).toBe("trusted");
    expect(verification.activeKey?.keyId).toBe(rotated.identity.keyId);
  });

  test("automatically rotates an expired witness key into durable secret state", async () => {
    const signingState = createEvidenceWitnessSigningState(
      "2026-07-19T00:00:00Z",
    );
    let encoded = encodeEvidenceWitnessSigningState(signingState);
    const service = createEvidenceWitnessService({
      loadSigningState: async () => encoded,
      origin: "https://witness.example",
      signingState,
      store: createMemoryEvidenceWitnessStore(),
      storeSigningState: async (next) => {
        encoded = next;
      },
    });
    const registry = await service.maintain({
      maxKeyAgeMs: 1_000,
      now: new Date("2026-07-19T00:00:02Z"),
    });

    expect(registry.activeKeyId).not.toBe(signingState.identity.keyId);
    expect(registry.transitions).toHaveLength(1);
    expect(JSON.parse(encoded).identity.keyId).toBe(registry.activeKeyId);
  });

  test("verifies a complete log and replays the original durable receipt", async () => {
    const { service } = serviceFixture();
    const evidence = createEvidenceSigningIdentity();
    const log = createEvidenceKeyTransparencyLog({ identity: evidence });
    const request = { contract: EVIDENCE_WITNESS_REQUEST_CONTRACT, log };
    const first = await service.checkpoint("paas-production", request);
    const replay = await service.checkpoint("paas-production", request);

    expect(replay.checkpoint).toEqual(first.checkpoint);
    expect(first.checkpoint.logHead).toBe(log.head);
    expect(first.registry.activeKeyId).toBe(first.checkpoint.witness.keyId);
  });

  test("rejects equivocation at one size and rollback from a larger log", async () => {
    const { service } = serviceFixture();
    const evidence = createEvidenceSigningIdentity();
    const other = createEvidenceSigningIdentity();
    const genesis = createEvidenceKeyTransparencyLog({ identity: evidence });
    const equivocation = createEvidenceKeyTransparencyLog({ identity: other });
    const nextIdentity = createEvidenceSigningIdentity();
    const transition = createEvidenceSigningKeyTransition({
      nextKey: evidenceVerificationKeyFrom(nextIdentity),
      previousIdentity: evidence,
    });
    const larger = appendEvidenceKeyRotation({
      identity: evidence,
      log: genesis,
      transition,
    });

    await service.checkpoint("equivocation-subject", {
      contract: EVIDENCE_WITNESS_REQUEST_CONTRACT,
      log: genesis,
    });
    await expect(
      service.checkpoint("equivocation-subject", {
        contract: EVIDENCE_WITNESS_REQUEST_CONTRACT,
        log: equivocation,
      }),
    ).rejects.toBeInstanceOf(EvidenceWitnessEquivocationError);

    const otherNextIdentity = createEvidenceSigningIdentity();
    const otherTransition = createEvidenceSigningKeyTransition({
      nextKey: evidenceVerificationKeyFrom(otherNextIdentity),
      previousIdentity: other,
    });
    const fork = appendEvidenceKeyRotation({
      identity: other,
      log: equivocation,
      transition: otherTransition,
    });
    await expect(
      service.checkpoint("equivocation-subject", {
        contract: EVIDENCE_WITNESS_REQUEST_CONTRACT,
        log: fork,
      }),
    ).rejects.toBeInstanceOf(EvidenceWitnessEquivocationError);

    await service.checkpoint("rollback-subject", {
      contract: EVIDENCE_WITNESS_REQUEST_CONTRACT,
      log: larger,
    });
    await expect(
      service.checkpoint("rollback-subject", {
        contract: EVIDENCE_WITNESS_REQUEST_CONTRACT,
        log: genesis,
      }),
    ).rejects.toBeInstanceOf(EvidenceWitnessRollbackError);
  });

  test("authenticates checkpoint writes while publishing witness keys", async () => {
    const { service } = serviceFixture();
    const handler = createEvidenceWitnessHttpHandler({
      authenticate: async (token) =>
        token === "valid-token" ? "paas-production" : null,
      service,
    });
    const evidence = createEvidenceSigningIdentity();
    const log = createEvidenceKeyTransparencyLog({ identity: evidence });
    const denied = await handler(
      new Request("https://witness.example/v1/checkpoints", {
        method: "POST",
      }),
    );
    const accepted = await handler(
      new Request("https://witness.example/v1/checkpoints", {
        body: JSON.stringify({
          contract: EVIDENCE_WITNESS_REQUEST_CONTRACT,
          log,
        }),
        headers: { authorization: "Bearer valid-token" },
        method: "POST",
      }),
    );
    const keys = await handler(new Request("https://witness.example/v1/keys"));

    expect(denied.status).toBe(401);
    expect(accepted.status).toBe(200);
    expect(keys.status).toBe(200);
    expect((await accepted.json()).checkpoint.logHead).toBe(log.head);
  });
});
