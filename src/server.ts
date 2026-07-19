#!/usr/bin/env bun
import { SQL } from "bun";
import {
  createEvidenceWitnessHttpHandler,
  createEvidenceWitnessService,
  parseEvidenceWitnessSigningState,
} from "./index";
import {
  createPostgresEvidenceWitnessStore,
  ensurePostgresEvidenceWitnessSchema,
} from "./postgres";

const required = (name: string) => {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`Missing required environment: ${name}`);
  return value;
};

const database = new SQL(required("DATABASE_URL"));
await ensurePostgresEvidenceWitnessSchema(database);
const encodedSigningState = required("EVIDENCE_WITNESS_SIGNING_STATE_JSON");
const signingState = parseEvidenceWitnessSigningState(
  JSON.parse(encodedSigningState),
);
const tokens = JSON.parse(required("EVIDENCE_WITNESS_TOKENS_JSON")) as Record<
  string,
  string
>;
const subjectsByToken = new Map(
  Object.entries(tokens).map(([subject, token]) => [token, subject]),
);
const service = createEvidenceWitnessService({
  loadSigningState: async () => encodedSigningState,
  origin: required("EVIDENCE_WITNESS_ORIGIN"),
  signingState,
  store: createPostgresEvidenceWitnessStore(database),
  storeSigningState: async () => {
    throw new Error(
      "Server-managed key rotation requires a durable secret-store integration",
    );
  },
});
const handler = createEvidenceWitnessHttpHandler({
  authenticate: async (token) => subjectsByToken.get(token) ?? null,
  service,
});
const port = Number(process.env.PORT ?? "3000");
if (!Number.isSafeInteger(port) || port < 1 || port > 65_535)
  throw new Error("PORT must be a valid TCP port");

Bun.serve({ fetch: handler, port });
