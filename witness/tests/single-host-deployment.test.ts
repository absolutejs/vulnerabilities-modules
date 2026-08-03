import { describe, expect, test } from "bun:test";

const root = new URL("../", import.meta.url);
const compose = await Bun.file(
  new URL("deploy/single-host/compose.yml", root),
).text();
const firewall = await Bun.file(
  new URL("deploy/single-host/absolutejs-evidence-witness-firewall", root),
).text();
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

  test("uses the image-local HTTPS client for portable health checks", () => {
    expect(compose).toContain("- wget");
    expect(compose).toContain("- --no-check-certificate");
    expect(compose).toContain("- https://127.0.0.1:3443/health");
    expect(compose).not.toContain("NODE_TLS_REJECT_UNAUTHORIZED");
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
    expect(backupCreate).toContain("dist/backupCli.js registry");
    expect(restoreVerify).toContain("docker network create --internal");
    expect(restoreVerify).toContain("pg_restore --no-owner --no-privileges");
    expect(restoreVerify).toContain("sha256sum --check --status");
    expect(restoreVerify).toContain('cmp "${staging}/registry.json"');
    expect(restoreVerify).toContain(
      "absolutejs.vulnerability-evidence-witness-backup-verification/v1",
    );
    expect(backupRecord).toContain("--network none");
    expect(backupRecord).toContain("dist/backupCli.js record-verification");
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
