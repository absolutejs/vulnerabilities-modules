#!/usr/bin/env bun
import { encryptedFileAdapter } from "@absolutejs/secrets/broker";
import {
  EVIDENCE_WITNESS_BACKUP_VERIFICATION_CONTRACT,
  evidenceWitnessKeyRegistryFrom,
  parseEvidenceWitnessBackupVerification,
  parseEvidenceWitnessSigningState,
} from "./index";

const signingStateName = "EVIDENCE_WITNESS_SIGNING_STATE_JSON";
const backupVerificationName = "EVIDENCE_WITNESS_BACKUP_VERIFICATION_JSON";
const maximumInputBytes = 16_384;

const required = (name: string) => {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`Missing required environment: ${name}`);
  return value;
};

const readBoundedStdin = async () => {
  const chunks: Uint8Array[] = [];
  let length = 0;
  for await (const chunk of process.stdin) {
    const bytes =
      typeof chunk === "string" ? new TextEncoder().encode(chunk) : chunk;
    length += bytes.byteLength;
    if (length > maximumInputBytes)
      throw new Error("Evidence witness backup record is too large");
    chunks.push(bytes);
  }
  const input = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    input.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(input);
};

const secrets = encryptedFileAdapter({
  key: {
    passphrase: required("EVIDENCE_WITNESS_SECRETS_PASSPHRASE"),
    type: "passphrase",
  },
  path: required("EVIDENCE_WITNESS_SECRETS_PATH"),
});

const command = process.argv[2];
if (command === "registry") {
  const encoded = await secrets.fetch(signingStateName);
  if (!encoded) throw new Error("Evidence witness signing state is missing");
  const state = parseEvidenceWitnessSigningState(JSON.parse(encoded));
  process.stdout.write(JSON.stringify(evidenceWitnessKeyRegistryFrom(state)));
} else if (command === "record-verification") {
  const parsed = parseEvidenceWitnessBackupVerification(
    JSON.parse(await readBoundedStdin()),
  );
  if (!secrets.put) throw new Error("Encrypted secret adapter is read-only");
  await secrets.put(backupVerificationName, JSON.stringify(parsed));
  console.log(EVIDENCE_WITNESS_BACKUP_VERIFICATION_CONTRACT);
} else {
  throw new Error(
    "Usage: absolute-vulnerability-witness-backup <registry|record-verification>",
  );
}
