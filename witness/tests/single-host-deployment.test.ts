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

  test("fails closed without a root-only runtime secret file", () => {
    expect(preflight).toContain("/run/*");
    expect(preflight).toContain("root:root:600");
    expect(preflight).toContain("1000:1000:400");
    expect(preflight).toContain("*@sha256:*");
    expect(preflight).toContain("*[!0-9a-f]*");
    expect(service).toContain("absolutejs-evidence-witness-preflight");
    expect(service).toContain("--pull never");
    expect(guide).toContain("below `/run`");
    expect(guide).toMatch(/disappears at\s+reboot/u);
    expect(guide).toContain("production secret manager");
    expect(guide).toMatch(/Public\s+launch requires a publicly trusted/u);
  });
});
