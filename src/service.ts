import {
  verifyEvidenceKeyTransparencyLog,
  type EvidenceKeyTransparencyLog,
} from "@absolutejs/vulnerabilities/evidence-transparency";
import { createEvidenceWitnessCheckpointForHead } from "@absolutejs/vulnerabilities/evidence-witness";
import {
  evidenceWitnessKeyRegistryFrom,
  encodeEvidenceWitnessSigningState,
  parseEvidenceWitnessSigningState,
  rotateEvidenceWitnessSigningState,
  type EvidenceWitnessKeyRegistry,
  type EvidenceWitnessSigningState,
} from "./signing";
import type { EvidenceWitnessStore } from "./store";

export const EVIDENCE_WITNESS_REQUEST_CONTRACT =
  "absolutejs.vulnerability-evidence-witness-request/v1" as const;

export type EvidenceWitnessRequest = {
  contract: typeof EVIDENCE_WITNESS_REQUEST_CONTRACT;
  log: EvidenceKeyTransparencyLog;
};

export type EvidenceWitnessResponse = {
  checkpoint: Awaited<
    ReturnType<EvidenceWitnessStore["observe"]>
  >["checkpoint"];
  registry: EvidenceWitnessKeyRegistry;
};

export const createEvidenceWitnessService = (options: {
  loadSigningState: () => Promise<string>;
  origin: string;
  signingState: EvidenceWitnessSigningState;
  store: EvidenceWitnessStore;
  storeSigningState: (encoded: string) => Promise<void>;
}) => {
  const origin = new URL(options.origin);
  if (origin.protocol !== "https:")
    throw new Error("Evidence witness origin must use HTTPS");
  let state = parseEvidenceWitnessSigningState(options.signingState);
  let mutationQueue = Promise.resolve();
  const refresh = async () => {
    state = parseEvidenceWitnessSigningState(
      JSON.parse(await options.loadSigningState()),
    );
    return state;
  };
  const registry = async () => {
    await refresh();
    return evidenceWitnessKeyRegistryFrom(state);
  };
  const checkpoint = async (
    subject: string,
    request: EvidenceWitnessRequest,
  ): Promise<EvidenceWitnessResponse> => {
    if (request.contract !== EVIDENCE_WITNESS_REQUEST_CONTRACT)
      throw new Error("Evidence witness request contract is unsupported");
    const [genesis] = request.log.entries;
    if (!genesis || genesis.event.kind !== "key_created")
      throw new Error("Evidence transparency genesis is missing");
    const verification = verifyEvidenceKeyTransparencyLog({
      log: request.log,
      trustedKeys: [genesis.event.key],
    });
    if (verification.trust !== "trusted")
      throw new Error("Evidence transparency log is invalid");
    const normalizedSubject = subject.trim();
    if (!normalizedSubject)
      throw new Error("Evidence witness subject is required");
    await refresh();
    const signed = createEvidenceWitnessCheckpointForHead({
      identity: state.identity,
      logHead: request.log.head,
      logSize: request.log.entries.length,
      origin: origin.href,
    });
    const observed = await options.store.observe({
      checkpoint: signed,
      history: request.log.entries.map(({ digest }) => digest),
      subject: normalizedSubject,
    });

    return {
      checkpoint: observed.checkpoint,
      registry: evidenceWitnessKeyRegistryFrom(state),
    };
  };
  const rotate = (rotatedAt = new Date().toISOString()) => {
    const queued = mutationQueue.then(async () => {
      await refresh();
      const next = rotateEvidenceWitnessSigningState(state, rotatedAt);
      await options.storeSigningState(encodeEvidenceWitnessSigningState(next));
      state = next;
      return evidenceWitnessKeyRegistryFrom(state);
    });
    mutationQueue = queued.then(
      () => undefined,
      () => undefined,
    );
    return queued;
  };
  const maintain = (input: { maxKeyAgeMs: number; now?: Date }) => {
    if (!Number.isSafeInteger(input.maxKeyAgeMs) || input.maxKeyAgeMs < 1)
      throw new Error("Evidence witness maximum key age is invalid");
    const now = input.now ?? new Date();
    const queued = mutationQueue.then(async () => {
      await refresh();
      const ageMs = now.getTime() - Date.parse(state.identity.createdAt);
      if (ageMs < input.maxKeyAgeMs)
        return evidenceWitnessKeyRegistryFrom(state);
      const next = rotateEvidenceWitnessSigningState(state, now.toISOString());
      await options.storeSigningState(encodeEvidenceWitnessSigningState(next));
      state = next;
      return evidenceWitnessKeyRegistryFrom(state);
    });
    mutationQueue = queued.then(
      () => undefined,
      () => undefined,
    );

    return queued;
  };

  return { checkpoint, maintain, registry, rotate };
};
