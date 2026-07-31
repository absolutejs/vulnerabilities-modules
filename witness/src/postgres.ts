import type { SignedEvidenceWitnessCheckpoint } from "@absolutejs/vulnerabilities/evidence-witness";
import type { SQL } from "bun";
import {
  EvidenceWitnessEquivocationError,
  EvidenceWitnessRollbackError,
  type EvidenceWitnessObservation,
  type EvidenceWitnessObservationInput,
  type EvidenceWitnessStore,
} from "./store";

const LOCK_NAME = "absolutejs:evidence-witness-observation";
const json = <T>(value: T | string) =>
  typeof value === "string" ? (JSON.parse(value) as T) : value;

export const ensurePostgresEvidenceWitnessSchema = async (sql: SQL) => {
  await sql.unsafe(`
    CREATE TABLE IF NOT EXISTS absolute_vulnerability_evidence_witness_observations (
      subject TEXT NOT NULL,
      log_size INTEGER NOT NULL CHECK (log_size > 0),
      log_head VARCHAR(71) NOT NULL,
      observed_at TIMESTAMPTZ NOT NULL,
      receipt JSONB NOT NULL,
      witness_key_id TEXT NOT NULL,
      PRIMARY KEY (subject, log_size)
    )
  `);
};

export const createPostgresEvidenceWitnessStore = (
  sql: SQL,
): EvidenceWitnessStore => {
  const latest = async (subject: string) => {
    const rows = await sql`
      SELECT receipt
      FROM absolute_vulnerability_evidence_witness_observations
      WHERE subject = ${subject}
      ORDER BY log_size DESC
      LIMIT 1
    `;
    const row = Array.from(
      rows as Array<{ receipt: SignedEvidenceWitnessCheckpoint | string }>,
    )[0];
    return row ? { checkpoint: json(row.receipt), subject } : null;
  };
  const observe = (input: EvidenceWitnessObservationInput) =>
    sql.begin(async (transaction) => {
      await transaction`
        SELECT pg_advisory_xact_lock(
          hashtext(${LOCK_NAME}), hashtext(${input.subject})
        )
      `;
      const rows = await transaction`
        SELECT log_head, log_size, receipt
        FROM absolute_vulnerability_evidence_witness_observations
        WHERE subject = ${input.subject}
        ORDER BY log_size DESC
        LIMIT 1
      `;
      const current = Array.from(
        rows as Array<{
          log_head: string;
          log_size: number;
          receipt: SignedEvidenceWitnessCheckpoint | string;
        }>,
      )[0];
      if (current?.log_size === input.checkpoint.logSize) {
        if (current.log_head !== input.checkpoint.logHead)
          throw new EvidenceWitnessEquivocationError(
            "Evidence transparency log equivocated at an observed size",
          );
        return {
          checkpoint: json(current.receipt),
          status: "replay" as const,
        };
      }
      if (current && current.log_size > input.checkpoint.logSize)
        throw new EvidenceWitnessRollbackError(
          "Evidence transparency log attempted to roll back",
        );
      if (current && input.history[current.log_size - 1] !== current.log_head)
        throw new EvidenceWitnessEquivocationError(
          "Evidence transparency log forked from observed history",
        );
      await transaction`
        INSERT INTO absolute_vulnerability_evidence_witness_observations (
          subject, log_size, log_head, observed_at, receipt, witness_key_id
        ) VALUES (
          ${input.subject}, ${input.checkpoint.logSize},
          ${input.checkpoint.logHead}, ${input.checkpoint.observedAt},
          ${JSON.stringify(input.checkpoint)}::jsonb,
          ${input.checkpoint.witness.keyId}
        )
      `;
      return {
        checkpoint: structuredClone(input.checkpoint),
        status: "accepted" as const,
      };
    });

  return { latest, observe };
};
