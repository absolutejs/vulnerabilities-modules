import { describe, expect, test } from "bun:test";

const repositoryRoot = new URL("../../", import.meta.url);
const workflow = await Bun.file(
  new URL(".github/workflows/witness-container.yml", repositoryRoot),
).text();
const deploymentGuide = await Bun.file(
  new URL("witness/deploy/README.md", repositoryRoot),
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
