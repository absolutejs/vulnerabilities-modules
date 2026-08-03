import { describe, expect, test } from "bun:test";

const repositoryRoot = new URL("../../", import.meta.url);
const workflow = await Bun.file(
  new URL(".github/workflows/witness-container.yml", repositoryRoot),
).text();
const deploymentGuide = await Bun.file(
  new URL("witness/deploy/README.md", repositoryRoot),
).text();
const dockerfile = await Bun.file(
  new URL("witness/Dockerfile", repositoryRoot),
).text();
const singleHostCompose = await Bun.file(
  new URL("witness/deploy/single-host/compose.yml", repositoryRoot),
).text();

const actionReferences = [
  ...workflow.matchAll(/^\s*uses:\s*([^\s#]+?)(?:\s+#.*)?$/gmu),
].map(([, reference]) => reference);

describe("Witness container supply chain", () => {
  test("pins every third-party action to an immutable commit", () => {
    expect(actionReferences.length).toBeGreaterThan(0);
    for (const reference of actionReferences) {
      expect(reference).toMatch(/@[0-9a-f]{40}$/u);
    }
  });

  test("scans before registry authentication and publishes no mutable tag", () => {
    const publication = workflow.slice(workflow.indexOf("  publish:"));
    const scan = publication.indexOf(
      "Fail on high or critical vulnerabilities",
    );
    const login = publication.indexOf("Log in to GHCR after validation");
    const push = publication.indexOf(
      "Push only the immutable full-revision tag",
    );

    expect(publication).not.toBe(workflow);
    expect(scan).toBeGreaterThan(-1);
    expect(login).toBeGreaterThan(scan);
    expect(push).toBeGreaterThan(login);
    expect(publication).toContain("severity-cutoff: high");
    expect(publication).toContain("Retain failed vulnerability evidence");
    expect(publication).toContain("if: failure()");
    expect(publication).toContain(
      "witness-vulnerability-report-${{ github.sha }}",
    );
    expect(workflow).not.toContain("type=ref,event=branch");
    expect(workflow).not.toMatch(/vulnerabilities-witness:(?:main|latest)/u);
  });

  test("retains an SBOM and immediately verified keyless image evidence", () => {
    expect(workflow).toContain("id-token: write");
    expect(workflow).toContain("format: spdx-json");
    expect(workflow).toContain(
      "./node_modules/.bin/absolute-attest provenance",
    );
    expect(workflow).toContain(
      "./node_modules/.bin/absolute-attest publish-image",
    );
    expect(workflow).toContain("attestations.json");
    expect(workflow).toContain("image-reference.txt");
  });

  test("scans the exact support image shipped by the host contract", () => {
    const [postgresReference] =
      singleHostCompose.match(/postgres@sha256:[0-9a-f]{64}/u) ?? [];

    expect(postgresReference).toBeTruthy();
    expect(workflow).toContain(`image: ${postgresReference}`);
    expect(workflow).toContain("id: postgres_scan");
    expect(workflow.match(/grype-version: v0\.116\.1/gu)).toHaveLength(2);
    expect(workflow).toContain("severity-cutoff: high");
    expect(workflow).toContain("evidence/postgres-grype.json");
    expect(workflow).toContain("if: always() && steps.scan.outputs.json != ''");
    expect(workflow).toContain(
      "if: always() && steps.postgres_scan.outputs.json != ''",
    );
    expect(workflow).toContain("if-no-files-found: warn");
    expect(workflow).toMatch(
      /Retain failed vulnerability evidence[\s\S]*path: \|[\s\S]*evidence\/grype\.json[\s\S]*evidence\/postgres-grype\.json/u,
    );
  });

  test("uses the exact minimized Bun runtime selected by the vulnerability gate", () => {
    expect(dockerfile).toContain("FROM oven/bun:1.3.14-alpine AS runtime");
    expect(dockerfile).toContain(
      'LABEL org.opencontainers.image.source="https://github.com/absolutejs/vulnerabilities-modules"',
    );
    expect(dockerfile).toContain("RUN apk upgrade --no-cache");
    expect(dockerfile).not.toContain("FROM oven/bun:1.3.14-slim AS runtime");
    expect(dockerfile).not.toMatch(/^FROM\s+[^\s]+:(?:latest|main)\b/mu);
    expect(workflow.match(/--user 65532:65532/gu)).toHaveLength(2);
    expect(workflow.match(/--network none/gu)).toHaveLength(2);
  });

  test("requires digest-pinned deployment and independent witness boundaries", () => {
    expect(deploymentGuide).toContain(
      "ghcr.io/absolutejs/vulnerabilities-witness@sha256:<digest>",
    );
    expect(deploymentGuide).toContain("different administrative account");
    expect(deploymentGuide).toContain(
      "different HTTPS origin and failure domain",
    );
    expect(deploymentGuide).toContain("Mutable tags");
  });
});
