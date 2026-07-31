import type {
  ManagedVulnerabilityFinding,
  RemediationExecution,
  RemediationPlan,
  RemediationVerification,
  VulnerabilityRiskAssessment,
  VexDecision,
  VexFindingApplication,
} from "@absolutejs/vulnerabilities";
import type {
  ReportDetermination,
  ReportDisposition,
  ReportedSecurityIssue,
} from "./contracts";

export type FindingReportContext = {
  assetName: string;
  executions: readonly RemediationExecution[];
  finding: ManagedVulnerabilityFinding;
  plan: RemediationPlan | null;
  risk: VulnerabilityRiskAssessment | null;
  sourceReference?: string | null;
  verifications: readonly RemediationVerification[];
  vexApplication: VexFindingApplication | null;
  vexDecision: VexDecision | null;
};

const classification = (
  input: FindingReportContext,
): {
  determination: ReportDetermination;
  disposition: ReportDisposition;
} => {
  const activeVex =
    input.vexApplication?.endedAt === null && input.vexDecision !== null;
  if (
    activeVex &&
    (input.vexDecision?.status === "not_affected" ||
      input.vexDecision?.status === "fixed")
  )
    return {
      determination: "false_positive",
      disposition:
        input.vexDecision.status === "fixed"
          ? "vendor_patched"
          : "false_positive",
    };
  if (input.finding.status === "fixed")
    return { determination: "real", disposition: "remediated" };
  if (
    input.plan?.status === "succeeded" &&
    !input.verifications.some(({ status }) => status === "passed")
  )
    return { determination: "real", disposition: "awaiting_verification" };
  if (input.finding.status === "accepted_risk")
    return { determination: "real", disposition: "accepted_risk" };
  if (input.finding.status === "remediation_planned")
    return { determination: "real", disposition: "remediation_planned" };
  if (input.finding.status === "remediating")
    return { determination: "real", disposition: "remediating" };
  if (input.finding.status === "mitigated")
    return { determination: "real", disposition: "remediated" };
  if (input.finding.status === "false_positive")
    return { determination: "false_positive", disposition: "false_positive" };
  return { determination: "real", disposition: "open" };
};

const response = (
  input: FindingReportContext,
  disposition: ReportDisposition,
) => {
  if (disposition === "vendor_patched")
    return (
      input.vexDecision?.statement ??
      "The installed vendor package contains the security fix."
    );
  if (disposition === "false_positive")
    return (
      input.vexDecision?.statement ??
      "Reviewed evidence shows that the reported vulnerability is not applicable."
    );
  if (disposition === "remediated")
    return "Deployment evidence and later inventory verification show that the finding has been remediated.";
  if (disposition === "awaiting_verification")
    return "The approved release was deployed; a later clean inventory observation is still required before closure.";
  if (disposition === "remediation_planned")
    return "A remediation plan has been approved for an exact deployment release.";
  if (disposition === "remediating")
    return "The approved remediation is currently executing.";
  if (disposition === "accepted_risk")
    return "The finding is real and is retained under an explicit risk-acceptance decision.";
  return "The finding is confirmed and remains open.";
};

export const createReportedIssueFromFinding = (
  input: FindingReportContext,
): ReportedSecurityIssue => {
  const { determination, disposition } = classification(input);
  const passed = input.verifications
    .filter(({ status }) => status === "passed")
    .sort((left, right) => right.observedAt.localeCompare(left.observedAt))[0];
  const evidence = [
    ...(input.vexDecision?.evidence ?? []),
    ...input.executions.flatMap((execution) => execution.evidence),
    ...input.verifications.flatMap((verification) => verification.evidence),
  ];
  const targetReleaseIds = [
    ...new Set(
      input.plan?.actions.flatMap(({ toVersion }) =>
        toVersion === null ? [] : [toVersion],
      ) ?? [],
    ),
  ];

  return {
    affectedSurface: `${input.assetName} / ${input.finding.componentId}`,
    determination,
    disposition,
    evidence,
    id: input.finding.id,
    remediation: input.plan
      ? {
          status: input.plan.status,
          summary: input.plan.rollbackSummary,
          targetReleaseIds,
          verifiedAt: passed?.observedAt ?? null,
        }
      : null,
    response: response(input, disposition),
    score: null,
    severity: input.finding.severity,
    sourceReference: input.sourceReference ?? null,
    title: input.finding.vulnerabilityIds.join(", "),
    vulnerabilityIds: [...input.finding.vulnerabilityIds],
  };
};
