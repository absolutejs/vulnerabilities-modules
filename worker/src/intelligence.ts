import { createHash } from "node:crypto";
import {
  createMemoryFeedStore,
  correlateVulnerabilityInventory,
  assessVulnerabilityRisk,
  applyVexDecision,
  completeRemediationExecution,
  createRemediationPlan,
  endVexApplication,
  selectVexDecision,
  startRemediationExecution,
  syncFeed,
  verifyRemediationExecution,
  type FeedAdapter,
  type FeedSnapshotStore,
  type FeedSyncRunStore,
  type FeedSyncResult,
  type EvidenceReference,
  type ManagedFindingStore,
  type ManagedVulnerabilityFinding,
  type RemediationDeployment,
  type RemediationExecutionStore,
  type RemediationPlan,
  type RemediationPlanStore,
  type RemediationVerificationStore,
  type VulnerabilityAsset,
  type VulnerabilityAdvisory,
  type VulnerabilityComponent,
  type VulnerabilityObservationStore,
  type VulnerabilityRiskAssessmentStore,
  type VexDecision,
  type VexDecisionStore,
  type VexFindingApplicationStore,
} from "@absolutejs/vulnerabilities";
import {
  createEpssAdapter,
  type EpssScore,
} from "@absolutejs/vulnerabilities-epss";
import {
  createKevAdapter,
  type KevEntry,
} from "@absolutejs/vulnerabilities-kev";
import {
  createOsvAdapter,
  type OsvQuery,
} from "@absolutejs/vulnerabilities-osv";
import type { PostgresVulnerabilityStore } from "@absolutejs/vulnerabilities-postgres";
import {
  createUbuntuAdapter,
  type UbuntuComponent,
} from "@absolutejs/vulnerabilities-ubuntu";

export type VulnerabilityVexConfiguration = {
  decision: VexDecision;
  tenantId: string;
};

export type VulnerabilityIntelligenceAdapters = {
  epss: FeedAdapter<EpssScore>;
  kev: FeedAdapter<KevEntry>;
  osv: FeedAdapter<VulnerabilityAdvisory>;
  ubuntu: FeedAdapter<VulnerabilityAdvisory>;
};

export type VulnerabilityIntelligenceStores = {
  epss: FeedSnapshotStore<EpssScore>;
  kev: FeedSnapshotStore<KevEntry>;
  osv: FeedSnapshotStore<VulnerabilityAdvisory>;
  ubuntu: FeedSnapshotStore<VulnerabilityAdvisory>;
};

export type VulnerabilityIntelligencePersistence = {
  findings: ManagedFindingStore;
  history: FeedSyncRunStore;
  observations: VulnerabilityObservationStore;
  remediationExecutions: RemediationExecutionStore;
  remediationPlans: RemediationPlanStore;
  remediationVerifications: RemediationVerificationStore;
  riskAssessments: VulnerabilityRiskAssessmentStore;
  stores: VulnerabilityIntelligenceStores;
  vexApplications: VexFindingApplicationStore;
  vexDecisions: VexDecisionStore;
};

export type VulnerabilityVexReconciliationResult = {
  applied: number;
  ended: number;
  expired: number;
  falsePositives: number;
  fixed: number;
  invalid: number;
};

const EMPTY_VEX_RESULT: VulnerabilityVexReconciliationResult = {
  applied: 0,
  ended: 0,
  expired: 0,
  falsePositives: 0,
  fixed: 0,
  invalid: 0,
};

const reconcileFindingVex = async (input: {
  applications: VexFindingApplicationStore;
  decisions: readonly VulnerabilityVexConfiguration["decision"][];
  findings: ManagedFindingStore;
  finding: ManagedVulnerabilityFinding;
  productId: string;
  reconciledAt: string;
}) => {
  const current = await input.applications.get(
    input.finding.tenantId,
    input.finding.id,
  );
  const selection = selectVexDecision({
    decisions: input.decisions,
    finding: input.finding,
    now: input.reconciledAt,
    productId: input.productId,
  });
  const evaluationCounts: Pick<
    VulnerabilityVexReconciliationResult,
    "expired" | "invalid"
  > = {
    expired: selection.evaluations.filter(({ status }) => status === "expired")
      .length,
    invalid: selection.evaluations.filter(({ status }) => status === "invalid")
      .length,
  };
  if (!selection.decision) {
    if (!current || current.endedAt !== null)
      return { ...EMPTY_VEX_RESULT, ...evaluationCounts };
    const result = endVexApplication({
      application: current,
      endedAt: input.reconciledAt,
      finding: input.finding,
      findingPresent: input.finding.lastSeenAt === input.reconciledAt,
    });
    await Promise.all([
      input.findings.save(result.finding),
      input.applications.save(result.application),
    ]);

    return { ...EMPTY_VEX_RESULT, ...evaluationCounts, ended: 1 };
  }
  if (current?.endedAt === null && current.decisionId === selection.decision.id)
    return { ...EMPTY_VEX_RESULT, ...evaluationCounts };
  const result = applyVexDecision({
    appliedAt: input.reconciledAt,
    decision: selection.decision,
    finding: input.finding,
  });
  await Promise.all([
    input.findings.save(result.finding),
    input.applications.save(result.application),
  ]);

  return {
    ...EMPTY_VEX_RESULT,
    ...evaluationCounts,
    applied: 1,
    falsePositives: Number(result.finding.status === "false_positive"),
    fixed: Number(result.finding.status === "fixed"),
  };
};

export const reconcileVulnerabilityVex = async (input: {
  applications: VexFindingApplicationStore;
  decisions: readonly VulnerabilityVexConfiguration[];
  decisionStore: VexDecisionStore;
  findings: ManagedFindingStore;
  inventory: readonly VulnerabilityInventoryTarget[];
  reconciledAt: string;
}) => {
  const decisionsByTenant = Map.groupBy(
    input.decisions,
    ({ tenantId }) => tenantId,
  );
  await Promise.all(
    [...decisionsByTenant].map(([tenantId, configured]) =>
      input.decisionStore.saveMany(
        tenantId,
        configured.map(({ decision }) => decision),
      ),
    ),
  );
  const results = (
    await Promise.all(
      input.inventory.map(async ({ asset }) => {
        const configured = (decisionsByTenant.get(asset.tenantId) ?? [])
          .filter(({ decision }) => decision.productId === asset.id)
          .map(({ decision }) => decision);
        const findings = await input.findings.list({
          assetId: asset.id,
          limit: 1_000,
          tenantId: asset.tenantId,
        });

        return Promise.all(
          findings.map((finding) =>
            reconcileFindingVex({
              applications: input.applications,
              decisions: configured,
              finding,
              findings: input.findings,
              productId: asset.id,
              reconciledAt: input.reconciledAt,
            }),
          ),
        );
      }),
    )
  ).flat();

  return results.reduce<VulnerabilityVexReconciliationResult>(
    (totals, result) => ({
      applied: totals.applied + result.applied,
      ended: totals.ended + result.ended,
      expired: totals.expired + result.expired,
      falsePositives: totals.falsePositives + result.falsePositives,
      fixed: totals.fixed + result.fixed,
      invalid: totals.invalid + result.invalid,
    }),
    EMPTY_VEX_RESULT,
  );
};

export type VulnerabilityInventoryTarget = {
  asset: VulnerabilityAsset;
  components: VulnerabilityComponent[];
  evidence?: EvidenceReference;
};

export type VulnerabilityRemediationDeploymentProvider = (
  assetId: string,
) => Promise<RemediationDeployment | null>;

const remediationId = (prefix: string, parts: readonly string[]) =>
  `${prefix}_${createHash("sha256").update(JSON.stringify(parts)).digest("hex")}`;

export const createVulnerabilityRemediationDrafts = async (input: {
  createdAt: string;
  findings: ManagedFindingStore;
  inventory: readonly VulnerabilityInventoryTarget[];
  plans: RemediationPlanStore;
}) => {
  const created = await Promise.all(
    input.inventory.map(async ({ asset }) => {
      const [findings, plans] = await Promise.all([
        input.findings.list({
          assetId: asset.id,
          limit: 1_000,
          tenantId: asset.tenantId,
        }),
        input.plans.list({ limit: 1_000, tenantId: asset.tenantId }),
      ]);
      const plannedFindingIds = new Set(
        plans.flatMap(({ findingIds }) => findingIds),
      );
      const eligible = findings.filter(
        ({ id, status }) =>
          (status === "confirmed" || status === "reopened") &&
          !plannedFindingIds.has(id),
      );
      const drafts = eligible.map((finding) =>
        createRemediationPlan({
          actions: [
            {
              assetId: asset.id,
              componentId: finding.componentId,
              fromVersion: asset.version,
              id: remediationId("action", [finding.id]),
              kind: "rebuild",
              requiresRestart: true,
              toVersion: null,
            },
          ],
          createdAt: input.createdAt,
          createdBy: "absolutejs-vulnerability-worker",
          findings: [finding],
          id: remediationId("plan", [finding.id]),
          rollbackSummary:
            "Reactivate the previously retained deployment release.",
        }),
      );
      await Promise.all(
        drafts.map((plan) => input.plans.save(asset.tenantId, plan)),
      );

      return drafts.length;
    }),
  );

  return { created: created.reduce((total, count) => total + count, 0) };
};

const deploymentEvidence = (deployment: RemediationDeployment) => ({
  collectedAt: deployment.activatedAt,
  digest: null,
  kind: "verification" as const,
  source: "absolutejs-deploy",
  uri: `deployment://${deployment.assetId}/releases/${deployment.releaseId}`,
});

const executeApprovedRemediation = async (input: {
  deployments: VulnerabilityRemediationDeploymentProvider;
  executions: RemediationExecutionStore;
  findings: ManagedFindingStore;
  plan: RemediationPlan;
  plans: RemediationPlanStore;
  tenantId: string;
}) => {
  if (
    input.plan.approvedAt === null ||
    input.plan.actions.some(({ toVersion }) => toVersion === null)
  )
    return 0;
  const deployments = await Promise.all(
    [...new Set(input.plan.actions.map(({ assetId }) => assetId))].map(
      input.deployments,
    ),
  );
  if (deployments.some((deployment) => deployment === null)) return 0;
  const observed = deployments.filter(
    (deployment): deployment is RemediationDeployment => deployment !== null,
  );
  if (
    input.plan.actions.some(
      (action) =>
        observed.find(({ assetId }) => assetId === action.assetId)
          ?.releaseId !== action.toVersion,
    )
  )
    return 0;
  const findings = await Promise.all(
    input.plan.findingIds.map((findingId) =>
      input.findings.get(input.tenantId, findingId),
    ),
  );
  if (findings.some((finding) => finding === null)) return 0;
  const managed = findings.filter(
    (finding): finding is ManagedVulnerabilityFinding => finding !== null,
  );
  const started = startRemediationExecution({
    executionId: remediationId("execution", [
      input.plan.id,
      ...observed.map(({ releaseId }) => releaseId).sort(),
    ]),
    findings: managed,
    plan: input.plan,
    startedAt: input.plan.approvedAt,
  });
  const completedAt = observed.reduce(
    (latest, { activatedAt }) => (activatedAt > latest ? activatedAt : latest),
    observed[0]!.activatedAt,
  );
  const completed = completeRemediationExecution({
    completedAt,
    evidence: observed.map(deploymentEvidence),
    execution: started.execution,
    message: "The approved deployment release is active.",
    plan: started.plan,
    status: "succeeded",
  });
  await Promise.all([
    input.executions.save(input.tenantId, completed.execution),
    input.findings.saveMany(started.findings),
    input.plans.save(input.tenantId, completed.plan),
  ]);

  return 1;
};

const verifySucceededRemediation = async (input: {
  deployments: VulnerabilityRemediationDeploymentProvider;
  executions: RemediationExecutionStore;
  findings: ManagedFindingStore;
  observedAt: string;
  plan: RemediationPlan;
  tenantId: string;
  verifications: RemediationVerificationStore;
}) => {
  const executions = await input.executions.list(input.tenantId, input.plan.id);
  const execution = executions.find(({ status }) => status === "succeeded");
  if (!execution || execution.completedAt === null) return null;
  const prior = await input.verifications.list(input.tenantId, execution.id);
  if (prior.some(({ status }) => status === "passed")) return null;
  const deployments = await Promise.all(
    [...new Set(input.plan.actions.map(({ assetId }) => assetId))].map(
      input.deployments,
    ),
  );
  if (deployments.some((deployment) => deployment === null)) return null;
  const observed = deployments.filter(
    (deployment): deployment is RemediationDeployment => deployment !== null,
  );
  const findings = await Promise.all(
    input.plan.findingIds.map((findingId) =>
      input.findings.get(input.tenantId, findingId),
    ),
  );
  if (findings.some((finding) => finding === null)) return null;
  const result = verifyRemediationExecution({
    deployments: observed,
    evidence: observed.map((deployment) => ({
      ...deploymentEvidence(deployment),
      collectedAt: input.observedAt,
      source: "absolutejs-inventory",
    })),
    execution,
    findings: findings.filter(
      (finding): finding is ManagedVulnerabilityFinding => finding !== null,
    ),
    observedAt: input.observedAt,
    plan: input.plan,
    verificationId: remediationId("verification", [
      execution.id,
      input.observedAt,
    ]),
  });
  await Promise.all([
    input.findings.saveMany(result.findings),
    input.verifications.save(input.tenantId, result.verification),
  ]);

  return result.verification;
};

export const reconcileVulnerabilityRemediation = async (input: {
  deployments: VulnerabilityRemediationDeploymentProvider;
  executions: RemediationExecutionStore;
  findings: ManagedFindingStore;
  inventory: readonly VulnerabilityInventoryTarget[];
  observedAt: string;
  plans: RemediationPlanStore;
  verifications: RemediationVerificationStore;
}) => {
  const tenants = [
    ...new Set(input.inventory.map(({ asset }) => asset.tenantId)),
  ];
  const executed = await Promise.all(
    tenants.map(async (tenantId) => {
      const plans = await input.plans.list({
        limit: 1_000,
        status: "approved",
        tenantId,
      });

      return Promise.all(
        plans.map((plan) =>
          executeApprovedRemediation({
            deployments: input.deployments,
            executions: input.executions,
            findings: input.findings,
            plan,
            plans: input.plans,
            tenantId,
          }),
        ),
      );
    }),
  );
  const verified = await Promise.all(
    tenants.map(async (tenantId) => {
      const plans = await input.plans.list({
        limit: 1_000,
        status: "succeeded",
        tenantId,
      });

      return Promise.all(
        plans.map((plan) =>
          verifySucceededRemediation({
            deployments: input.deployments,
            executions: input.executions,
            findings: input.findings,
            observedAt: input.observedAt,
            plan,
            tenantId,
            verifications: input.verifications,
          }),
        ),
      );
    }),
  );
  const results = verified.flat().filter((result) => result !== null);

  return {
    executed: executed
      .flat()
      .reduce<number>((total, count) => total + count, 0),
    failed: results.filter(({ status }) => status === "failed").length,
    fixed: results.reduce(
      (total, { fixedFindingIds }) => total + fixedFindingIds.length,
      0,
    ),
    verified: results.filter(({ status }) => status === "passed").length,
  };
};

export type VulnerabilityIntelligenceSnapshot = {
  epss: FeedSyncResult<EpssScore>;
  kev: FeedSyncResult<KevEntry>;
  osv: FeedSyncResult<VulnerabilityAdvisory>;
  ubuntu: FeedSyncResult<VulnerabilityAdvisory>;
};

type IntelligenceFetch = (
  input: Parameters<typeof globalThis.fetch>[0],
  init?: Parameters<typeof globalThis.fetch>[1],
) => ReturnType<typeof globalThis.fetch>;

export const correlateVulnerabilityIntelligenceInventory = async (input: {
  advisories: readonly VulnerabilityAdvisory[];
  findings: ManagedFindingStore;
  inventory: readonly VulnerabilityInventoryTarget[];
  observations: VulnerabilityObservationStore;
  observedAt: string;
}) => {
  const results = await Promise.all(
    input.inventory.map(async (target) => {
      const existingFindings = await input.findings.list({
        assetId: target.asset.id,
        limit: 1_000,
        tenantId: target.asset.tenantId,
      });
      const result = correlateVulnerabilityInventory({
        advisories: input.advisories,
        asset: target.asset,
        components: target.components,
        existingFindings,
        inventoryEvidence: target.evidence,
        observedAt: input.observedAt,
      });
      await Promise.all([
        input.findings.saveMany(result.upserts),
        input.observations.saveMany(target.asset.tenantId, result.observations),
      ]);

      return {
        findings: result.findings.length,
        observations: result.observations.length,
        resolved: result.resolved.length,
        unknown: result.evaluations.filter(({ status }) => status === "unknown")
          .length,
      };
    }),
  );

  return {
    assets: input.inventory.length,
    findings: results.reduce((total, result) => total + result.findings, 0),
    observations: results.reduce(
      (total, result) => total + result.observations,
      0,
    ),
    resolved: results.reduce((total, result) => total + result.resolved, 0),
    unknown: results.reduce((total, result) => total + result.unknown, 0),
  };
};

const explicitBoolean = (value: string | undefined) => value === "true";

const reachability = (value: string | undefined) => {
  if (value === "reachable" || value === "not_reachable") return value;

  return "unknown" as const;
};

const prioritizeVulnerabilityIntelligence = async (input: {
  assessedAt: string;
  epss: readonly EpssScore[];
  findings: ManagedFindingStore;
  inventory: readonly VulnerabilityInventoryTarget[];
  kev: readonly KevEntry[];
  riskAssessments: VulnerabilityRiskAssessmentStore;
}) => {
  const epssByCve = new Map(input.epss.map((score) => [score.cve, score]));
  const kevByCve = new Map(input.kev.map((entry) => [entry.cveId, entry]));
  const results = await Promise.all(
    input.inventory.map(async ({ asset }) => {
      const findings = await input.findings.list({
        assetId: asset.id,
        limit: 1_000,
        tenantId: asset.tenantId,
      });
      const active = findings.filter(
        ({ status }) =>
          status !== "fixed" &&
          status !== "mitigated" &&
          status !== "false_positive",
      );
      const assessments = active.map((finding) => {
        const cves = finding.vulnerabilityIds.filter((id) =>
          /^CVE-\d{4}-\d+$/u.test(id),
        );
        const [epss] = cves
          .map((id) => epssByCve.get(id))
          .filter((score): score is EpssScore => score !== undefined)
          .sort(
            (left, right) =>
              right.probability - left.probability ||
              right.percentile - left.percentile,
          );
        const [kev] = cves
          .map((id) => kevByCve.get(id))
          .filter((entry): entry is KevEntry => entry !== undefined)
          .sort((left, right) => left.dueDate.localeCompare(right.dueDate));

        return assessVulnerabilityRisk({
          assessedAt: input.assessedAt,
          assetCriticality: asset.criticality,
          finding,
          fixAvailable: explicitBoolean(asset.labels["security.fix_available"]),
          internetExposed: explicitBoolean(
            asset.labels["security.internet_exposed"],
          ),
          reachability: reachability(asset.labels["security.reachability"]),
          signals: {
            epss: epss
              ? {
                  percentile: epss.percentile,
                  probability: epss.probability,
                }
              : null,
            kev: kev
              ? {
                  dueDate: kev.dueDate,
                  knownRansomwareCampaignUse: kev.knownRansomwareCampaignUse,
                }
              : null,
          },
        });
      });
      await input.riskAssessments.saveMany(asset.tenantId, assessments);

      return assessments;
    }),
  );
  const assessments = results.flat();

  return {
    assessments: assessments.length,
    critical: assessments.filter(({ priority }) => priority === "critical")
      .length,
    emergency: assessments.filter(({ priority }) => priority === "emergency")
      .length,
    high: assessments.filter(({ priority }) => priority === "high").length,
  };
};

export { prioritizeVulnerabilityIntelligence };
export const createPostgresVulnerabilityIntelligencePersistence = (
  postgres: PostgresVulnerabilityStore,
): VulnerabilityIntelligencePersistence => ({
  findings: postgres.findings,
  history: postgres.syncRuns,
  observations: postgres.observations,
  remediationExecutions: postgres.remediationExecutions,
  remediationPlans: postgres.remediationPlans,
  remediationVerifications: postgres.remediationVerifications,
  riskAssessments: postgres.riskAssessments,
  stores: {
    epss: postgres.snapshots<EpssScore>(),
    kev: postgres.snapshots<KevEntry>(),
    osv: postgres.snapshots<VulnerabilityAdvisory>(),
    ubuntu: postgres.snapshots<VulnerabilityAdvisory>(),
  },
  vexApplications: postgres.vexApplications,
  vexDecisions: postgres.vexDecisions,
});
export const createVulnerabilityIntelligenceAdapters = (input: {
  cves: readonly string[];
  fetch?: IntelligenceFetch;
  osvQueries: readonly OsvQuery[];
  ubuntuComponents: readonly UbuntuComponent[];
}): VulnerabilityIntelligenceAdapters => ({
  epss: createEpssAdapter({
    cves: input.cves,
    ...(input.fetch ? { fetch: input.fetch } : {}),
  }),
  kev: createKevAdapter(input.fetch ? { fetch: input.fetch } : {}),
  osv: createOsvAdapter({
    ...(input.fetch ? { fetch: input.fetch } : {}),
    queries: input.osvQueries,
  }),
  ubuntu: createUbuntuAdapter({
    components: input.ubuntuComponents,
    ...(input.fetch ? { fetch: input.fetch } : {}),
  }),
});
export const createVulnerabilityIntelligenceMemoryStores =
  (): VulnerabilityIntelligenceStores => ({
    epss: createMemoryFeedStore<EpssScore>(),
    kev: createMemoryFeedStore<KevEntry>(),
    osv: createMemoryFeedStore<VulnerabilityAdvisory>(),
    ubuntu: createMemoryFeedStore<VulnerabilityAdvisory>(),
  });
export const refreshVulnerabilityIntelligence = async (input: {
  adapters: VulnerabilityIntelligenceAdapters;
  maxStaleMs: number;
  now?: number;
  signal?: AbortSignal;
  stores: VulnerabilityIntelligenceStores;
}): Promise<VulnerabilityIntelligenceSnapshot> => {
  const sync = <T>(adapter: FeedAdapter<T>, store: FeedSnapshotStore<T>) =>
    syncFeed({
      adapter,
      maxStaleMs: input.maxStaleMs,
      ...(input.now === undefined ? {} : { now: input.now }),
      ...(input.signal ? { signal: input.signal } : {}),
      store,
    });
  const [epss, kev, osv, ubuntu] = await Promise.all([
    sync(input.adapters.epss, input.stores.epss),
    sync(input.adapters.kev, input.stores.kev),
    sync(input.adapters.osv, input.stores.osv),
    sync(input.adapters.ubuntu, input.stores.ubuntu),
  ]);

  return { epss, kev, osv, ubuntu };
};
