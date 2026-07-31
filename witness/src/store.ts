import type { SignedEvidenceWitnessCheckpoint } from "@absolutejs/vulnerabilities/evidence-witness";

export type EvidenceWitnessObservation = {
  checkpoint: SignedEvidenceWitnessCheckpoint;
  subject: string;
};

export type EvidenceWitnessObservationInput = EvidenceWitnessObservation & {
  history: readonly `sha256:${string}`[];
};

export type EvidenceWitnessObservationResult = {
  checkpoint: SignedEvidenceWitnessCheckpoint;
  status: "accepted" | "replay";
};

export interface EvidenceWitnessStore {
  latest(subject: string): Promise<EvidenceWitnessObservation | null>;
  observe(
    observation: EvidenceWitnessObservationInput,
  ): Promise<EvidenceWitnessObservationResult>;
}

export class EvidenceWitnessEquivocationError extends Error {}
export class EvidenceWitnessRollbackError extends Error {}

const normalizedSubject = (subject: string) => {
  const value = subject.trim();
  if (!value) throw new Error("Evidence witness subject is required");
  return value;
};

export const createMemoryEvidenceWitnessStore = (): EvidenceWitnessStore => {
  const subjects = new Map<string, Map<number, EvidenceWitnessObservation>>();
  const latest = async (subject: string) => {
    const values = subjects.get(normalizedSubject(subject));
    if (!values || values.size === 0) return null;
    const size = Math.max(...values.keys());
    return structuredClone(values.get(size)!);
  };
  const observe = async (input: EvidenceWitnessObservationInput) => {
    const subject = normalizedSubject(input.subject);
    let values = subjects.get(subject);
    if (!values) {
      values = new Map();
      subjects.set(subject, values);
    }
    const existing = values.get(input.checkpoint.logSize);
    if (existing) {
      if (existing.checkpoint.logHead !== input.checkpoint.logHead)
        throw new EvidenceWitnessEquivocationError(
          "Evidence transparency log equivocated at an observed size",
        );
      return {
        checkpoint: structuredClone(existing.checkpoint),
        status: "replay" as const,
      };
    }
    const current = await latest(subject);
    if (current && current.checkpoint.logSize > input.checkpoint.logSize)
      throw new EvidenceWitnessRollbackError(
        "Evidence transparency log attempted to roll back",
      );
    if (
      current &&
      input.history[current.checkpoint.logSize - 1] !==
        current.checkpoint.logHead
    )
      throw new EvidenceWitnessEquivocationError(
        "Evidence transparency log forked from observed history",
      );
    const observation = structuredClone({
      checkpoint: input.checkpoint,
      subject,
    });
    values.set(input.checkpoint.logSize, observation);

    return {
      checkpoint: structuredClone(input.checkpoint),
      status: "accepted" as const,
    };
  };

  return { latest, observe };
};
