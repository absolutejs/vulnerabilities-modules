import { createHash } from "node:crypto";
import { Value } from "@sinclair/typebox/value";
import {
  VulnerabilitySecurityReportInputSchema,
  type ReportedSecurityIssue,
  type VulnerabilitySecurityReport,
  type VulnerabilitySecurityReportInput,
} from "./contracts";

const canonicalIssue = (
  issue: ReportedSecurityIssue,
): ReportedSecurityIssue => ({
  ...issue,
  evidence: [...issue.evidence].sort((left, right) =>
    `${left.kind}:${left.source}:${left.collectedAt}:${left.uri ?? ""}`.localeCompare(
      `${right.kind}:${right.source}:${right.collectedAt}:${right.uri ?? ""}`,
    ),
  ),
  remediation: issue.remediation
    ? {
        ...issue.remediation,
        targetReleaseIds: [...issue.remediation.targetReleaseIds].sort(),
      }
    : null,
  vulnerabilityIds: [...issue.vulnerabilityIds].sort(),
});

export const createVulnerabilitySecurityReport = (
  input: VulnerabilitySecurityReportInput,
): VulnerabilitySecurityReport => {
  if (!Value.Check(VulnerabilitySecurityReportInputSchema, input))
    throw new Error("Vulnerability security report input is invalid");
  const canonical: VulnerabilitySecurityReportInput = {
    generatedAt: new Date(input.generatedAt).toISOString(),
    issues: input.issues
      .map(canonicalIssue)
      .sort((left, right) => left.id.localeCompare(right.id)),
    preparedBy: input.preparedBy,
    preparedFor: input.preparedFor,
    reportId: input.reportId,
    scope: input.scope,
    source: {
      assessedAt: input.source.assessedAt
        ? new Date(input.source.assessedAt).toISOString()
        : null,
      name: input.source.name,
      reference: input.source.reference,
    },
    title: input.title,
  };
  const summary = {
    falsePositives: canonical.issues.filter(
      ({ determination }) => determination === "false_positive",
    ).length,
    informational: canonical.issues.filter(
      ({ determination }) => determination === "informational",
    ).length,
    open: canonical.issues.filter(({ disposition }) =>
      ["open", "remediation_planned", "remediating"].includes(disposition),
    ).length,
    real: canonical.issues.filter(
      ({ determination }) => determination === "real",
    ).length,
    remediated: canonical.issues.filter(({ disposition }) =>
      ["remediated", "vendor_patched"].includes(disposition),
    ).length,
    total: canonical.issues.length,
    verificationPending: canonical.issues.filter(
      ({ disposition }) => disposition === "awaiting_verification",
    ).length,
  };
  const digest = `sha256:${createHash("sha256")
    .update(JSON.stringify({ ...canonical, summary }))
    .digest("hex")}`;

  return { ...canonical, digest, summary };
};
