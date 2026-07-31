import {
  VULNERABILITY_CONTRACT_VERSION,
  type ManagedVulnerabilityFinding,
  type RemediationPlan,
  type VexDecision,
  type VexFindingApplication,
} from "@absolutejs/vulnerabilities";
import { describe, expect, test } from "bun:test";
import { Value } from "@sinclair/typebox/value";
import {
  createReportedIssueFromFinding,
  createVulnerabilitySecurityReport,
  renderVulnerabilitySecurityReportHtml,
  type ReportedSecurityIssue,
  VulnerabilitySecurityReportSchema,
} from "../src";

const timestamp = "2026-07-18T20:00:00.000Z";
const evidence = {
  collectedAt: timestamp,
  digest: null,
  kind: "vendor-status" as const,
  source: "ubuntu-security",
  uri: "https://ubuntu.com/security/CVE-2026-0001",
};
const finding: ManagedVulnerabilityFinding = {
  assetId: "project-1",
  componentId: "nginx",
  contract: VULNERABILITY_CONTRACT_VERSION,
  firstSeenAt: timestamp,
  id: `vuln_${"a".repeat(64)}`,
  lastSeenAt: timestamp,
  observationIds: ["observation-1"],
  severity: "high",
  status: "false_positive",
  tenantId: "tenant-1",
  vulnerabilityIds: ["CVE-2026-0001"],
};
const decision: VexDecision = {
  author: "security-team",
  contract: VULNERABILITY_CONTRACT_VERSION,
  createdAt: timestamp,
  evidence: [evidence],
  expiresAt: null,
  id: "decision-1",
  justification: "vendor_backport_applied",
  productId: finding.assetId,
  reviewedAt: timestamp,
  statement: "Ubuntu applied the security fix in the installed revision.",
  status: "fixed",
  vulnerabilityId: "CVE-2026-0001",
};
const application: VexFindingApplication = {
  appliedAt: timestamp,
  contract: VULNERABILITY_CONTRACT_VERSION,
  decisionId: decision.id,
  endedAt: null,
  findingId: finding.id,
  previousStatus: "confirmed",
  resultingStatus: "false_positive",
  tenantId: finding.tenantId,
};
const plan: RemediationPlan = {
  actions: [
    {
      assetId: finding.assetId,
      componentId: finding.componentId,
      fromVersion: "release-1",
      id: "action-1",
      kind: "rebuild",
      requiresRestart: true,
      toVersion: "release-2",
    },
  ],
  approvedAt: timestamp,
  approvedBy: "operator-1",
  contract: VULNERABILITY_CONTRACT_VERSION,
  createdAt: timestamp,
  createdBy: "worker",
  findingIds: [finding.id],
  id: "plan-1",
  rollbackSummary: "Reactivate release-1.",
  status: "approved",
};

describe("vulnerability security reports", () => {
  test("projects evidence-backed vendor fixes as scanner false positives", () => {
    const issue = createReportedIssueFromFinding({
      assetName: "Production web",
      executions: [],
      finding,
      plan,
      risk: null,
      sourceReference: "scan-13747781",
      verifications: [],
      vexApplication: application,
      vexDecision: decision,
    });

    expect(issue).toMatchObject({
      determination: "false_positive",
      disposition: "vendor_patched",
      response: decision.statement,
      vulnerabilityIds: ["CVE-2026-0001"],
    });
    expect(issue.evidence).toEqual([evidence]);
    expect(issue.remediation?.targetReleaseIds).toEqual(["release-2"]);
  });

  test("canonicalizes issue order and produces a stable digest", () => {
    const base: ReportedSecurityIssue = {
      affectedSurface: "Production web / nginx",
      determination: "real",
      disposition: "remediated",
      evidence: [evidence],
      id: "issue-b",
      remediation: null,
      response: "The configuration was corrected.",
      score: 5.3,
      severity: "medium",
      sourceReference: "page 32",
      title: "HSTS missing",
      vulnerabilityIds: [],
    };
    const input = {
      generatedAt: timestamp,
      issues: [
        { ...base, id: "issue-b" },
        { ...base, id: "issue-a" },
      ],
      preparedBy: "AbsoluteJS Security",
      preparedFor: "Client",
      reportId: "report-1",
      scope: "onspark.com",
      source: {
        assessedAt: "2026-07-17T20:59:48.000Z",
        name: "External scan",
        reference: "scan-13747781",
      },
      title: "Security Remediation Response",
    };
    const first = createVulnerabilitySecurityReport(input);
    const second = createVulnerabilitySecurityReport({
      ...input,
      issues: [...input.issues].reverse(),
    });

    expect(first.issues.map(({ id }) => id)).toEqual(["issue-a", "issue-b"]);
    expect(first.digest).toBe(second.digest);
    expect(first.summary).toMatchObject({ remediated: 2, total: 2 });
    expect(Value.Check(VulnerabilitySecurityReportSchema, first)).toBe(true);
  });

  test("renders escaped, self-contained, print-ready HTML", () => {
    const report = createVulnerabilitySecurityReport({
      generatedAt: timestamp,
      issues: [
        {
          affectedSurface: "web <script>alert(1)</script>",
          determination: "false_positive",
          disposition: "vendor_patched",
          evidence: [evidence],
          id: "issue-1",
          remediation: null,
          response: "Vendor backport verified.",
          score: null,
          severity: "high",
          sourceReference: "page 3",
          title: "nginx < upstream",
          vulnerabilityIds: ["CVE-2026-0001"],
        },
      ],
      preparedBy: "AbsoluteJS Security",
      preparedFor: "Client",
      reportId: "report-1",
      scope: "Production",
      source: { assessedAt: null, name: "External scan", reference: null },
      title: "Security Response",
    });
    const html = renderVulnerabilitySecurityReportHtml(report);

    expect(html).toContain("@media print");
    expect(html).toContain(report.digest);
    expect(html).toContain("default-src 'none'");
    expect(html).toContain("web &lt;script&gt;alert(1)&lt;/script&gt;");
    expect(html).not.toContain("<script>alert(1)</script>");
    expect(html).not.toContain("<script src=");
  });
});
