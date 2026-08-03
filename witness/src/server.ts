#!/usr/bin/env bun
import { SQL } from "bun";
import { encryptedFileAdapter } from "@absolutejs/secrets/broker";
import {
  createEvidenceWitnessHttpHandler,
  createEvidenceWitnessService,
  parseEvidenceWitnessSigningState,
} from "./index";
import {
  createPostgresEvidenceWitnessStore,
  ensurePostgresEvidenceWitnessSchema,
} from "./postgres";
import { evidenceWitnessTlsFilePaths } from "./serverTransport";
import { createEvidenceWitnessShutdown } from "./serverLifecycle";

const required = (name: string) => {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`Missing required environment: ${name}`);
  return value;
};

const positiveInteger = (name: string, fallback: number) => {
  const encoded = process.env[name]?.trim();
  if (!encoded) return fallback;
  const value = Number(encoded);
  if (!Number.isSafeInteger(value) || value < 1)
    throw new Error(`${name} must be a positive integer`);
  return value;
};

const signingStateName = "EVIDENCE_WITNESS_SIGNING_STATE_JSON";
const tokensName = "EVIDENCE_WITNESS_TOKENS_JSON";
const backupVerificationName = "EVIDENCE_WITNESS_BACKUP_VERIFICATION_JSON";
const masterPassphrase = required("EVIDENCE_WITNESS_SECRETS_PASSPHRASE");
const secrets = encryptedFileAdapter({
  key: { passphrase: masterPassphrase, type: "passphrase" },
  path: required("EVIDENCE_WITNESS_SECRETS_PATH"),
});
const loadOrBootstrap = async (name: string) => {
  const stored = await secrets.fetch(name);
  if (stored) return stored;
  const bootstrap = required(name);
  if (!secrets.put) throw new Error("Encrypted secret adapter is read-only");
  await secrets.put(name, bootstrap);
  return bootstrap;
};
const loadOptionalBootstrap = async (name: string) => {
  const stored = await secrets.fetch(name);
  if (stored) return stored;
  const bootstrap = process.env[name]?.trim();
  if (!bootstrap) return null;
  if (!secrets.put) throw new Error("Encrypted secret adapter is read-only");
  await secrets.put(name, bootstrap);
  return bootstrap;
};

const database = new SQL(required("DATABASE_URL"));
await ensurePostgresEvidenceWitnessSchema(database);
const encodedSigningState = await loadOrBootstrap(signingStateName);
const signingState = parseEvidenceWitnessSigningState(
  JSON.parse(encodedSigningState),
);
const tokens = JSON.parse(await loadOrBootstrap(tokensName)) as Record<
  string,
  string
>;
const subjectsByToken = new Map(
  Object.entries(tokens).map(([subject, token]) => [token, subject]),
);
const service = createEvidenceWitnessService({
  loadBackupVerification: async () => {
    const encoded = await loadOptionalBootstrap(backupVerificationName);
    return encoded ? JSON.parse(encoded) : null;
  },
  loadSigningState: async () => {
    const encoded = await secrets.fetch(signingStateName);
    if (!encoded) throw new Error("Evidence witness signing state is missing");
    return encoded;
  },
  origin: required("EVIDENCE_WITNESS_ORIGIN"),
  signingState,
  store: createPostgresEvidenceWitnessStore(database),
  storeSigningState: async (encoded) => {
    if (!secrets.put) throw new Error("Encrypted secret adapter is read-only");
    await secrets.put(signingStateName, encoded);
  },
});
const handler = createEvidenceWitnessHttpHandler({
  authenticate: async (token) => subjectsByToken.get(token) ?? null,
  service,
});
const port = Number(process.env.PORT ?? "3000");
if (!Number.isSafeInteger(port) || port < 1 || port > 65_535)
  throw new Error("PORT must be a valid TCP port");

const tlsPaths = evidenceWitnessTlsFilePaths();
const server = Bun.serve({
  fetch: handler,
  port,
  ...(tlsPaths
    ? { tls: { cert: Bun.file(tlsPaths.cert), key: Bun.file(tlsPaths.key) } }
    : {}),
});

const dayMs = 86_400_000;
const maxKeyAgeMs = positiveInteger(
  "EVIDENCE_WITNESS_KEY_MAX_AGE_MS",
  90 * dayMs,
);
const maintenanceIntervalMs = positiveInteger(
  "EVIDENCE_WITNESS_MAINTENANCE_INTERVAL_MS",
  3_600_000,
);
const maintain = () =>
  service
    .maintain({ maxKeyAgeMs })
    .catch((error) =>
      console.error("Evidence witness key maintenance failed", error),
    );
const maintenanceTimer = setInterval(
  () => void maintain(),
  maintenanceIntervalMs,
);
maintenanceTimer.unref();
void maintain();

const shutdown = createEvidenceWitnessShutdown({
  clearMaintenance: () => clearInterval(maintenanceTimer),
  stopServer: () => server.stop(true),
  closeDatabase: () => database.close(),
});
const handleShutdown = () => {
  void shutdown()
    .then(() => process.exit(0))
    .catch((error: unknown) => {
      console.error("Evidence witness graceful shutdown failed", error);
      process.exit(1);
    });
};
process.on("SIGINT", handleShutdown);
process.on("SIGTERM", handleShutdown);
