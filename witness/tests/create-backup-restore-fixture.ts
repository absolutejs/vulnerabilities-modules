import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createEvidenceWitnessSigningState } from "../src";

const root = process.argv[2];
if (!root) throw new Error("fixture root is required");
await mkdir(root, { recursive: true });

const signingState = createEvidenceWitnessSigningState("2026-08-03T00:00:00Z");
const lines = [
  "POSTGRES_DB=witness_restore_test",
  "POSTGRES_USER=witness_restore_test",
  "POSTGRES_PASSWORD=synthetic-restore-password",
  "DATABASE_URL=postgres://witness_restore_test:synthetic-restore-password@postgres:5432/witness_restore_test",
  "EVIDENCE_WITNESS_ORIGIN=https://witness-restore.test",
  "EVIDENCE_WITNESS_SECRETS_PATH=/var/lib/absolutejs/secrets.enc.json",
  "EVIDENCE_WITNESS_SECRETS_PASSPHRASE=synthetic-restore-passphrase",
  `EVIDENCE_WITNESS_SIGNING_STATE_JSON=${JSON.stringify(signingState)}`,
  'EVIDENCE_WITNESS_TOKENS_JSON={"paas":"synthetic-backup-token"}',
];
await writeFile(join(root, "witness.env"), `${lines.join("\n")}\n`, {
  mode: 0o600,
});
