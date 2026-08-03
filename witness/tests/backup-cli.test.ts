import { afterEach, describe, expect, test } from "bun:test";
import { encryptedFileAdapter } from "@absolutejs/secrets/broker";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createEvidenceWitnessSigningState,
  EVIDENCE_WITNESS_BACKUP_VERIFICATION_CONTRACT,
  evidenceWitnessKeyRegistryFrom,
} from "../src/index";

const temporaryDirectories: string[] = [];
afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { force: true, recursive: true })),
  );
});

const createFixture = async () => {
  const root = await mkdtemp(join(tmpdir(), "absolutejs-witness-backup-"));
  temporaryDirectories.push(root);
  const path = join(root, "secrets.enc.json");
  const passphrase = "synthetic-backup-cli-passphrase";
  const adapter = encryptedFileAdapter({
    key: { passphrase, type: "passphrase" },
    path,
  });
  const state = createEvidenceWitnessSigningState("2026-08-03T00:00:00Z");
  await adapter.put?.(
    "EVIDENCE_WITNESS_SIGNING_STATE_JSON",
    JSON.stringify(state),
  );
  return { adapter, passphrase, path, state };
};

const run = async (
  command: string,
  testFixture: Awaited<ReturnType<typeof createFixture>>,
  input = "",
) => {
  const child = Bun.spawn(["bun", "src/backupCli.ts", command], {
    env: {
      ...process.env,
      EVIDENCE_WITNESS_SECRETS_PASSPHRASE: testFixture.passphrase,
      EVIDENCE_WITNESS_SECRETS_PATH: testFixture.path,
    },
    stderr: "pipe",
    stdin: "pipe",
    stdout: "pipe",
  });
  child.stdin.write(input);
  child.stdin.end();
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ]);
  return { exitCode, stderr, stdout };
};

describe("evidence witness backup CLI", () => {
  test("derives only the public registry from encrypted signing state", async () => {
    const testFixture = await createFixture();
    const result = await run("registry", testFixture);
    expect(result.exitCode).toBe(0);
    expect(result.stderr).toBe("");
    expect(JSON.parse(result.stdout)).toEqual(
      evidenceWitnessKeyRegistryFrom(testFixture.state),
    );
    expect(result.stdout).not.toContain(testFixture.passphrase);
  });

  test("validates and records bounded restore evidence", async () => {
    const testFixture = await createFixture();
    const record = {
      contract: EVIDENCE_WITNESS_BACKUP_VERIFICATION_CONTRACT,
      databaseArtifactDigest: `sha256:${"a".repeat(64)}`,
      databaseRestoredAt: "2026-08-03T01:00:00Z",
      signingStateArtifactDigest: `sha256:${"b".repeat(64)}`,
      signingStateRestoredAt: "2026-08-03T01:01:00Z",
      verifiedAt: "2026-08-03T01:02:00Z",
    };
    const result = await run(
      "record-verification",
      testFixture,
      JSON.stringify(record),
    );
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe(
      EVIDENCE_WITNESS_BACKUP_VERIFICATION_CONTRACT,
    );
    const reopened = encryptedFileAdapter({
      key: { passphrase: testFixture.passphrase, type: "passphrase" },
      path: testFixture.path,
    });
    expect(
      await reopened.fetch("EVIDENCE_WITNESS_BACKUP_VERIFICATION_JSON"),
    ).toBe(JSON.stringify(record));
  });

  test("rejects oversized restore evidence without changing state", async () => {
    const testFixture = await createFixture();
    const result = await run(
      "record-verification",
      testFixture,
      "x".repeat(16_385),
    );
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toContain("backup record is too large");
    expect(
      await testFixture.adapter.fetch(
        "EVIDENCE_WITNESS_BACKUP_VERIFICATION_JSON",
      ),
    ).toBeNull();
  });
});
