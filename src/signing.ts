import {
  createEvidenceSigningIdentity,
  createEvidenceSigningKeyTransition,
  evidenceVerificationKeyFrom,
  parseEvidenceSigningIdentity,
  parseEvidenceVerificationKey,
  verifyEvidenceSigningKeyTransition,
  type EvidenceSigningIdentity,
  type EvidenceSigningKeyTransition,
  type EvidenceVerificationKey,
} from "@absolutejs/vulnerabilities/evidence-bundle";

const SIGNING_STATE_VERSION = 1;

export type EvidenceWitnessSigningState = {
  identity: EvidenceSigningIdentity;
  transitions: EvidenceSigningKeyTransition[];
  version: typeof SIGNING_STATE_VERSION;
};

export type EvidenceWitnessKeyRegistry = {
  activeKeyId: string;
  keys: EvidenceVerificationKey[];
  transitions: EvidenceSigningKeyTransition[];
  version: typeof SIGNING_STATE_VERSION;
};

const keysMatch = (
  left: EvidenceVerificationKey,
  right: EvidenceVerificationKey,
) =>
  left.keyId === right.keyId &&
  left.fingerprint === right.fingerprint &&
  left.publicKey === right.publicKey;

const registryKeys = (state: EvidenceWitnessSigningState) => {
  const keys = new Map<string, EvidenceVerificationKey>();
  const add = (key: EvidenceVerificationKey) => keys.set(key.keyId, key);
  add(evidenceVerificationKeyFrom(state.identity));
  for (const transition of state.transitions) {
    add(transition.previousKey);
    add(transition.nextKey);
  }

  return [...keys.values()].sort((left, right) =>
    left.createdAt.localeCompare(right.createdAt),
  );
};

export const createEvidenceWitnessSigningState = (
  createdAt = new Date().toISOString(),
): EvidenceWitnessSigningState => ({
  identity: createEvidenceSigningIdentity({ createdAt }),
  transitions: [],
  version: SIGNING_STATE_VERSION,
});

export const parseEvidenceWitnessSigningState = (
  value: unknown,
): EvidenceWitnessSigningState => {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error("Evidence witness signing state is invalid");
  const input = value as Partial<EvidenceWitnessSigningState>;
  if (
    input.version !== SIGNING_STATE_VERSION ||
    !input.identity ||
    !Array.isArray(input.transitions)
  )
    throw new Error("Evidence witness signing state is invalid");
  const identity = parseEvidenceSigningIdentity(input.identity);
  const transitions = input.transitions.map((transition) => {
    if (!verifyEvidenceSigningKeyTransition(transition))
      throw new Error("Evidence witness key transition is invalid");
    return structuredClone(transition);
  });
  const registry = evidenceWitnessKeyRegistryFrom({
    identity,
    transitions,
    version: SIGNING_STATE_VERSION,
  });
  if (
    verifyEvidenceWitnessKeyRegistry({
      registry,
      trustedKeys: [registry.keys[0]!],
    }).trust !== "trusted"
  )
    throw new Error("Evidence witness key chain is disconnected");

  return { identity, transitions, version: SIGNING_STATE_VERSION };
};

export const encodeEvidenceWitnessSigningState = (
  state: EvidenceWitnessSigningState,
) => JSON.stringify(parseEvidenceWitnessSigningState(state));

export const rotateEvidenceWitnessSigningState = (
  state: EvidenceWitnessSigningState,
  rotatedAt = new Date().toISOString(),
): EvidenceWitnessSigningState => {
  const current = parseEvidenceWitnessSigningState(state);
  const identity = createEvidenceSigningIdentity({ createdAt: rotatedAt });
  const transition = createEvidenceSigningKeyTransition({
    nextKey: evidenceVerificationKeyFrom(identity),
    previousIdentity: current.identity,
    rotatedAt,
  });

  return {
    identity,
    transitions: [...current.transitions, transition],
    version: SIGNING_STATE_VERSION,
  };
};

export const evidenceWitnessKeyRegistryFrom = (
  state: EvidenceWitnessSigningState,
): EvidenceWitnessKeyRegistry => ({
  activeKeyId: state.identity.keyId,
  keys: registryKeys(state),
  transitions: structuredClone(state.transitions),
  version: SIGNING_STATE_VERSION,
});

export const verifyEvidenceWitnessKeyRegistry = (input: {
  registry: EvidenceWitnessKeyRegistry;
  trustedKeys: readonly EvidenceVerificationKey[];
}) => {
  try {
    if (input.registry.version !== SIGNING_STATE_VERSION)
      throw new Error("Evidence witness registry version is unsupported");
    const keys = input.registry.keys.map(parseEvidenceVerificationKey);
    const transitions = input.registry.transitions.map((transition) => {
      if (!verifyEvidenceSigningKeyTransition(transition))
        throw new Error("Evidence witness key transition is invalid");
      return transition;
    });
    let cursor = keys.find(({ keyId }) => keyId === input.registry.activeKeyId);
    if (!cursor) throw new Error("Evidence witness active key is missing");
    const visited = new Set<string>();
    let traversed = 0;
    while (!input.trustedKeys.some((trusted) => keysMatch(trusted, cursor!))) {
      if (visited.has(cursor.keyId))
        throw new Error("Evidence witness key chain contains a cycle");
      visited.add(cursor.keyId);
      const transition = transitions.find((entry) =>
        keysMatch(entry.nextKey, cursor!),
      );
      if (!transition)
        return { activeKey: cursor, trust: "untrusted" as const };
      cursor = transition.previousKey;
      traversed += 1;
    }
    if (traversed !== transitions.length)
      throw new Error(
        "Evidence witness key registry contains disconnected history",
      );

    return {
      activeKey: keys.find(
        ({ keyId }) => keyId === input.registry.activeKeyId,
      )!,
      trust: "trusted" as const,
    };
  } catch {
    return { activeKey: null, trust: "untrusted" as const };
  }
};
