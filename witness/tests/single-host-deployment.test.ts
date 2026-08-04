import { describe, expect, test } from "bun:test";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = new URL("../", import.meta.url);
const firewallUrl = new URL(
  "deploy/single-host/absolutejs-evidence-witness-firewall",
  root,
);
const compose = await Bun.file(
  new URL("deploy/single-host/compose.yml", root),
).text();
const firewall = await Bun.file(firewallUrl).text();
const preflight = await Bun.file(
  new URL("deploy/single-host/absolutejs-evidence-witness-preflight", root),
).text();
const service = await Bun.file(
  new URL("deploy/single-host/absolutejs-evidence-witness.service", root),
).text();
const secretsInitializer = await Bun.file(
  new URL("deploy/single-host/absolutejs-evidence-witness-secrets-init", root),
).text();
const runtimeMaterializer = await Bun.file(
  new URL(
    "deploy/single-host/absolutejs-evidence-witness-runtime-materialize",
    root,
  ),
).text();
const runtimeCleanup = await Bun.file(
  new URL(
    "deploy/single-host/absolutejs-evidence-witness-runtime-cleanup",
    root,
  ),
).text();
const backupCreate = await Bun.file(
  new URL("deploy/single-host/absolutejs-evidence-witness-backup-create", root),
).text();
const restoreVerify = await Bun.file(
  new URL(
    "deploy/single-host/absolutejs-evidence-witness-restore-verify",
    root,
  ),
).text();
const backupRecord = await Bun.file(
  new URL("deploy/single-host/absolutejs-evidence-witness-backup-record", root),
).text();
const backupUpload = await Bun.file(
  new URL("deploy/single-host/absolutejs-evidence-witness-backup-upload", root),
).text();
const backupService = await Bun.file(
  new URL(
    "deploy/single-host/absolutejs-evidence-witness-backup.service",
    root,
  ),
).text();
const backupTimer = await Bun.file(
  new URL("deploy/single-host/absolutejs-evidence-witness-backup.timer", root),
).text();
const guide = await Bun.file(
  new URL("deploy/single-host/README.md", root),
).text();
const postgresService = compose.slice(
  compose.indexOf("  postgres:"),
  compose.indexOf("  witness-secrets-init:"),
);
const witnessService = compose.slice(compose.indexOf("  witness:\n"));

const runFirewallWithMockIptables = async (cidrs: string) => {
  const directory = await mkdtemp(join(tmpdir(), "witness-firewall-"));
  const iptables = join(directory, "iptables");
  const log = join(directory, "iptables.log");
  await writeFile(
    iptables,
    '#!/bin/sh\nprintf \'%s\\n\' "$*" >> "${IPTABLES_LOG}"\n',
  );
  await chmod(iptables, 0o700);

  try {
    const process = Bun.spawn(["sh", fileURLToPath(firewallUrl), cidrs], {
      env: {
        ...globalThis.process.env,
        IPTABLES_LOG: log,
        PATH: `${directory}:${globalThis.process.env.PATH ?? ""}`,
      },
      stderr: "pipe",
      stdout: "pipe",
    });
    const [exitCode, stderr] = await Promise.all([
      process.exited,
      new Response(process.stderr).text(),
    ]);
    const commands = await readFile(log, "utf8").catch(() => "");

    return { commands, exitCode, stderr };
  } finally {
    await rm(directory, { force: true, recursive: true });
  }
};

describe("single-host witness deployment", () => {
  test("pins support images and requires one preverified witness digest", () => {
    expect(compose).toContain(
      "image: ${EVIDENCE_WITNESS_IMAGE:?immutable witness image is required}",
    );
    expect(compose).toContain("postgres@sha256:");
    expect(compose).not.toContain("caddy");
    expect(compose.match(/pull_policy: never/g)?.length).toBe(3);
    expect(compose).not.toMatch(/image:\s+[^\n]+:(?:main|latest)\b/u);
  });

  test("keeps the data tier private and drops container privileges", () => {
    expect(compose).toContain("internal: true");
    expect(compose.match(/cap_drop:\n\s+- ALL/g)?.length).toBe(3);
    expect(compose.match(/no-new-privileges:true/g)?.length).toBe(3);
    expect(compose).toMatch(
      /witness-secrets-init:[\s\S]*?cap_add:[\s\S]*?- CHOWN\n\s+- FOWNER/u,
    );
    expect(postgresService).not.toContain("ports:");
  });

  test("uses the PostgreSQL 18 persistent-volume layout", () => {
    expect(postgresService).toContain("postgres-data:/var/lib/postgresql");
    expect(postgresService).not.toContain(
      "postgres-data:/var/lib/postgresql/data",
    );
  });

  test("denies every non-database connection from the service network", () => {
    expect(firewall).toContain("-s 172.30.81.0/24 -j REJECT");
    expect(firewall).toContain("-s 172.30.82.0/24 -j REJECT");
    expect(firewall).not.toContain("--dports 80,443 -j RETURN");
  });

  test("fails closed unless witness ingress is limited to exact public IPv4 hosts", () => {
    expect(service).toContain(
      "absolutejs-evidence-witness-firewall ${WITNESS_INGRESS_IPV4_CIDRS}",
    );
    expect(firewall).toContain("witness ingress CIDRs are required");
    expect(firewall).toContain('case "${cidr}" in');
    expect(firewall).toContain("*/32)");
    expect(firewall).toContain("witness ingress CIDR is not publicly routable");
    expect(firewall).toContain(
      '-s "${cidr}" -d 172.30.82.2/32 -p tcp --dport 3443 -j RETURN',
    );
    expect(firewall).toContain(
      "-d 172.30.82.2/32 -p tcp --dport 3443 -j REJECT",
    );
    expect(guide).toContain("WITNESS_INGRESS_IPV4_CIDRS=93.184.216.34/32");
    expect(guide).toContain("provider firewall");
  });

  test("validates the complete ingress allowlist before changing iptables", async () => {
    for (const invalid of [
      "",
      "0.0.0.0/0",
      "10.0.0.1/32",
      "169.254.169.254/32",
      "203.0.113.10/32",
      "8.8.8.8/24",
      "008.8.8.8/32",
      "8.8.8.8/32, 1.1.1.1/32",
    ]) {
      const result = await runFirewallWithMockIptables(invalid);
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr).toContain("witness ingress");
      expect(result.commands).toBe("");
    }
  });

  test("allows reviewed hosts before rejecting all other witness ingress", async () => {
    const result = await runFirewallWithMockIptables("8.8.8.8/32,1.1.1.1/32");
    expect(result.exitCode).toBe(0);
    expect(result.stderr).toBe("");
    expect(result.commands).toContain(
      "-A ABSOLUTEJS-WITNESS -s 8.8.8.8/32 -d 172.30.82.2/32 -p tcp --dport 3443 -j RETURN",
    );
    expect(result.commands).toContain(
      "-A ABSOLUTEJS-WITNESS -s 1.1.1.1/32 -d 172.30.82.2/32 -p tcp --dport 3443 -j RETURN",
    );
    const reject =
      "-A ABSOLUTEJS-WITNESS -d 172.30.82.2/32 -p tcp --dport 3443 -j REJECT";
    expect(result.commands).toContain(reject);
    expect(result.commands.indexOf("-s 1.1.1.1/32")).toBeLessThan(
      result.commands.indexOf(reject),
    );
  });

  test("uses the image-local HTTPS client for portable health checks", () => {
    expect(compose).toContain("- wget");
    expect(compose).toContain("- --no-check-certificate");
    expect(compose).toContain("- https://127.0.0.1:3443/health");
    expect(compose).not.toContain("NODE_TLS_REJECT_UNAUTHORIZED");
  });

  test("reaps child processes created by recurring TLS health checks", () => {
    expect(witnessService).toContain("    init: true\n");
    expect(witnessService.indexOf("    init: true\n")).toBeLessThan(
      witnessService.indexOf("    healthcheck:\n"),
    );
  });

  test("fails closed without a root-only runtime secret file", () => {
    expect(preflight).toContain("/run/*");
    expect(preflight).toContain("root:root:600");
    expect(preflight.match(/root:root 0711/g)?.length).toBe(2);
    expect(preflight).toContain("65532:65532:400");
    expect(compose).toContain('user: "65532:65532"');
    expect(compose).toContain("absolutejs-evidence-witness-secrets-init:ro");
    expect(compose).not.toMatch(/\b1000:1000\b/u);
    expect(secretsInitializer).toContain('chown 65532:65532 "${secrets_file}"');
    expect(secretsInitializer).toContain('chown 0:0 "${secrets_directory}"');
    expect(secretsInitializer).toMatch(
      /chown 65532:65532 "\$\{secrets_directory\}"\s*$/u,
    );
    expect(secretsInitializer).toContain('chmod 0600 "${secrets_file}"');
    expect(secretsInitializer).toContain("must not be a symbolic link");
    expect(preflight).toContain("*@sha256:*");
    expect(preflight).toContain("*[!0-9a-f]*");
    expect(service).toContain("absolutejs-evidence-witness-preflight");
    expect(service).toContain("--pull never");
    expect(guide).toContain("below `/run`");
    expect(guide).toMatch(/disappears at\s+reboot/u);
    expect(guide).toContain("production secret manager");
    expect(guide).toMatch(/Public\s+launch requires a publicly trusted/u);
  });

  test("supports host-bound encrypted reboot materialization without making it mandatory", () => {
    expect(service).toContain("ImportCredential=absolutejs.witness.*");
    expect(service).toContain(
      "absolutejs-evidence-witness-runtime-materialize ${WITNESS_RUNTIME_ENV_FILE}",
    );
    expect(service).not.toContain("runtime-materialize %d");
    expect(service).not.toContain(
      "runtime-materialize ${CREDENTIALS_DIRECTORY}",
    );
    expect(service.indexOf("runtime-materialize")).toBeLessThan(
      service.indexOf("absolutejs-evidence-witness-preflight"),
    );
    expect(service).toContain("absolutejs-evidence-witness-runtime-cleanup");
    expect(runtimeMaterializer).toContain(
      "witness encrypted credential set is incomplete",
    );
    expect(runtimeMaterializer).toContain(
      "credentials_directory=${CREDENTIALS_DIRECTORY:-}",
    );
    expect(runtimeMaterializer).toContain('[ "${present}" -eq 0 ]');
    expect(runtimeMaterializer).toContain("must not be symbolic links");
    expect(runtimeMaterializer).toContain("install -o 0 -g 0 -m 0600");
    expect(runtimeMaterializer).toContain("install -o 65532 -g 65532 -m 0400");
    expect(runtimeCleanup).toContain(".systemd-encrypted-credentials");
    expect(guide).toContain("systemd-creds encrypt --with-key=host");
    expect(guide).toContain(
      "does not protect against that host's root operator",
    );
  });

  test("creates runtime-only backups and verifies restores without external egress", () => {
    expect(backupCreate).toContain(
      "witness plaintext backup archive must remain below /run",
    );
    expect(backupCreate).toContain("pg_dump --format=custom");
    expect(backupCreate).toContain("secrets.enc.json");
    expect(backupCreate).toContain("--network none");
    expect(backupCreate).toContain(
      "--memory 128m --memory-swap 128m --pids-limit 32 --cpus 0.5",
    );
    expect(backupCreate).toContain('docker pause "${witness_container}"');
    expect(backupCreate).toContain('docker unpause "${witness_container}"');
    expect(backupCreate).not.toContain("docker stop");
    expect(backupCreate).toContain(
      "witness did not become healthy after backup snapshot",
    );
    expect(backupCreate).toContain("dist/backupCli.js registry");
    expect(restoreVerify).toContain("docker network create --internal");
    expect(restoreVerify).toContain("pg_restore --no-owner --no-privileges");
    expect(restoreVerify).toContain("sha256sum --check --status");
    expect(restoreVerify).toContain('cmp "${staging}/registry.json"');
    expect(restoreVerify).toContain(
      "absolutejs.vulnerability-evidence-witness-backup-verification/v1",
    );
    expect(backupRecord).toContain("--network none");
    expect(backupRecord).toContain(
      "--memory 128m --memory-swap 128m --pids-limit 32 --cpus 0.5",
    );
    expect(backupRecord).toContain("dist/backupCli.js record-verification");
    expect(backupRecord).toContain("> 16384 )); then");
    expect(backupRecord).not.toContain("16_384");
    expect(backupRecord).toContain(
      'docker stop --time 30 "${witness_container}"',
    );
    expect(backupRecord).toContain('docker start "${witness_container}"');
    expect(backupRecord).not.toContain("--publish");
  });

  test("encrypts automated backups to fixed independent destinations", () => {
    expect(backupUpload).toContain("WITNESS_BACKUP_RECIPIENT_FINGERPRINT");
    expect(backupUpload).toContain("AWS_EC2_METADATA_DISABLED=true");
    expect(backupUpload).toContain("--expected-bucket-owner");
    expect(backupUpload).toContain("--checksum-algorithm SHA256");
    expect(backupUpload).toContain(
      "^https://[a-z0-9-]+\\.digitaloceanspaces\\.com$",
    );
    expect(backupUpload.match(/aws s3api put-object/gu)).toHaveLength(2);
    expect(backupUpload.indexOf('rm -f "${archive}"')).toBeLessThan(
      backupUpload.indexOf("aws s3api put-object"),
    );
    expect(backupService).toContain(
      "LoadCredentialEncrypted=absolutejs.witness.backup-upload.env",
    );
    expect(backupService).toContain("ProtectSystem=strict");
    expect(backupService).toContain(
      "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
    );
    expect(backupTimer).toContain("OnCalendar=*-*-* 01,07,13,19:00:00 UTC");
    expect(backupTimer).toContain("RandomizedDelaySec=15m");
    expect(guide).toMatch(/S3 bucket with Object Lock\s+default retention/u);
    expect(guide).toContain("DigitalOcean Spaces bucket with versioning");
  });
});
