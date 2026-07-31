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

export const EVIDENCE_WITNESS_BACKUP_VERIFICATION_CONTRACT =
  "absolutejs.vulnerability-evidence-witness-backup-verification/v1" as const;
export const EVIDENCE_WITNESS_STATUS_CONTRACT =
  "absolutejs.vulnerability-evidence-witness-status/v2" as const;

export type EvidenceWitnessBackupVerification = {
  contract: typeof EVIDENCE_WITNESS_BACKUP_VERIFICATION_CONTRACT;
  databaseArtifactDigest: `sha256:${string}`;
  databaseRestoredAt: string;
  signingStateArtifactDigest: `sha256:${string}`;
  signingStateRestoredAt: string;
  verifiedAt: string;
};

export type EvidenceWitnessStatus = {
  backup: EvidenceWitnessBackupVerification | null;
  checkedAt: string;
  contract: typeof EVIDENCE_WITNESS_STATUS_CONTRACT;
  latestCheckpoint: EvidenceWitnessResponse["checkpoint"] | null;
  registry: EvidenceWitnessKeyRegistry;
};

const timestamp = (value: string, label: string) => {
  if (!Number.isFinite(Date.parse(value)))
    throw new Error(`${label} is invalid`);
  return value;
};

const digest = (value: string, label: string) => {
  if (!/^sha256:[a-f0-9]{64}$/u.test(value))
    throw new Error(`${label} is invalid`);
  return value as `sha256:${string}`;
};

export const parseEvidenceWitnessBackupVerification = (
  value: unknown,
): EvidenceWitnessBackupVerification => {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error("Evidence witness backup verification is invalid");
  const input = value as Partial<EvidenceWitnessBackupVerification>;
  if (input.contract !== EVIDENCE_WITNESS_BACKUP_VERIFICATION_CONTRACT)
    throw new Error("Evidence witness backup verification is unsupported");
  return {
    contract: input.contract,
    databaseArtifactDigest: digest(
      input.databaseArtifactDigest ?? "",
      "Evidence witness database backup digest",
    ),
    databaseRestoredAt: timestamp(
      input.databaseRestoredAt ?? "",
      "Evidence witness database restore time",
    ),
    signingStateArtifactDigest: digest(
      input.signingStateArtifactDigest ?? "",
      "Evidence witness signing-state backup digest",
    ),
    signingStateRestoredAt: timestamp(
      input.signingStateRestoredAt ?? "",
      "Evidence witness signing-state restore time",
    ),
    verifiedAt: timestamp(
      input.verifiedAt ?? "",
      "Evidence witness backup verification time",
    ),
  };
};

export const createEvidenceWitnessService = (options: {
  loadBackupVerification?: () => Promise<unknown | null>;
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
  const status = async (subject: string): Promise<EvidenceWitnessStatus> => ({
    backup: options.loadBackupVerification
      ? await options
          .loadBackupVerification()
          .then((value) =>
            value === null
              ? null
              : parseEvidenceWitnessBackupVerification(value),
          )
      : null,
    checkedAt: new Date().toISOString(),
    contract: EVIDENCE_WITNESS_STATUS_CONTRACT,
    latestCheckpoint: await options.store
      .latest(subject)
      .then((observation) => observation?.checkpoint ?? null),
    registry: await registry(),
  });
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

  return { checkpoint, maintain, registry, rotate, status };
};
