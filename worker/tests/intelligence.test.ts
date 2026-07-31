import {
  VULNERABILITY_CONTRACT_VERSION,
  type FeedAdapter,
  type FeedRecord,
  type ManagedVulnerabilityFinding,
  type RemediationExecution,
  type RemediationPlan,
  type RemediationVerification,
  type VulnerabilityAdvisory,
  type VulnerabilityObservation,
  type VulnerabilityRiskAssessment,
  type VexDecision,
  type VexFindingApplication,
} from "@absolutejs/vulnerabilities";
import type { EpssScore } from "@absolutejs/vulnerabilities-epss";
import type { KevEntry } from "@absolutejs/vulnerabilities-kev";
import { describe, expect, test } from "bun:test";
import {
  createVulnerabilityIntelligenceMemoryStores,
  createVulnerabilityRemediationDrafts,
  correlateVulnerabilityIntelligenceInventory,
  prioritizeVulnerabilityIntelligence,
  reconcileVulnerabilityRemediation,
  reconcileVulnerabilityVex,
  refreshVulnerabilityIntelligence,
  type VulnerabilityIntelligenceAdapters,
} from "../src/intelligence";

const timestamp = "2026-07-18T19:00:00Z";
const advisory: VulnerabilityAdvisory = {
  affected: [],
  aliases: ["CVE-2026-0001"],
  contract: VULNERABILITY_CONTRACT_VERSION,
  details: null,
  id: "CVE-2026-0001",
  modifiedAt: timestamp,
  publishedAt: timestamp,
  severity: [],
  source: {
    fetchedAt: timestamp,
    name: "fixture",
    revision: "1",
    url: "https://security.example/CVE-2026-0001",
  },
  summary: "Fixture advisory",
  withdrawnAt: null,
};
const kev: KevEntry = {
  cveId: "CVE-2026-0001",
  cwes: ["CWE-79"],
  dateAdded: "2026-07-18",
  dueDate: "2026-07-25",
  knownRansomwareCampaignUse: "Unknown",
  notes: "",
  product: "Fixture",
  requiredAction: "Apply the vendor update.",
  shortDescription: "Fixture description",
  vendorProject: "Fixture vendor",
  vulnerabilityName: "Fixture vulnerability",
};
const epss: EpssScore = {
  cve: "CVE-2026-0001",
  date: "2026-07-18",
  percentile: 0.97,
  probability: 0.31,
};

const adapter = <T>(
  id: string,
  record: FeedRecord<T>,
  failure = false,
): FeedAdapter<T> => ({
  descriptor: {
    id,
    name: `${id} fixture`,
    url: `https://security.example/${id}`,
  },
  fetch: async () => {
    if (failure) throw new Error(`${id} unavailable`);

    return {
      cursor: { etag: null, lastModified: null, token: null },
      fetchedAt: timestamp,
      records: [record],
      replaceAll: true,
      revision: "1",
      status: "updated",
    };
  },
});

const adapters = (kevFailure = false): VulnerabilityIntelligenceAdapters => ({
  epss: adapter("first-epss", {
    id: epss.cve,
    modifiedAt: `${epss.date}T00:00:00Z`,
    value: epss,
  }),
  kev: adapter(
    "cisa-kev",
    { id: kev.cveId, modifiedAt: timestamp, value: kev },
    kevFailure,
  ),
  osv: adapter("osv", {
    id: advisory.id,
    modifiedAt: advisory.modifiedAt,
    value: advisory,
  }),
  ubuntu: adapter("ubuntu", {
    id: advisory.id,
    modifiedAt: advisory.modifiedAt,
    value: advisory,
  }),
});

describe("vulnerability intelligence refresh", () => {
  test("refreshes all providers through independent stores", async () => {
    const result = await refreshVulnerabilityIntelligence({
      adapters: adapters(),
      maxStaleMs: 60_000,
      stores: createVulnerabilityIntelligenceMemoryStores(),
    });
    expect(Object.values(result).map(({ status }) => status)).toEqual([
      "updated",
      "updated",
      "updated",
      "updated",
    ]);
    expect(result.epss.snapshot?.records[0]?.value.probability).toBe(0.31);
    expect(result.kev.snapshot?.records[0]?.value.dueDate).toBe("2026-07-25");
  });

  test("isolates a provider failure from successful refreshes", async () => {
    const result = await refreshVulnerabilityIntelligence({
      adapters: adapters(true),
      maxStaleMs: 60_000,
      stores: createVulnerabilityIntelligenceMemoryStores(),
    });
    expect(result.kev.status).toBe("failed");
    expect(result.kev.error).toBe("cisa-kev unavailable");
    expect(result.osv.status).toBe("updated");
    expect(result.ubuntu.status).toBe("updated");
    expect(result.epss.status).toBe("updated");
  });
});

describe("vulnerability VEX reconciliation", () => {
  test("applies reviewed false positives and reopens present findings after expiry", async () => {
    const finding: ManagedVulnerabilityFinding = {
      assetId: "deployment-1",
      componentId: "fixture-component",
      contract: VULNERABILITY_CONTRACT_VERSION,
      firstSeenAt: timestamp,
      id: `vuln_${"b".repeat(64)}`,
      lastSeenAt: timestamp,
      observationIds: ["observation-1"],
      severity: "high",
      status: "confirmed",
      tenantId: "tenant-1",
      vulnerabilityIds: ["CVE-2026-0001"],
    };
    const findings = new Map([[finding.id, finding]]);
    const applications = new Map<string, VexFindingApplication>();
    const decisions = new Map<string, VexDecision>();
    const decision: VexDecision = {
      author: "security-team",
      contract: VULNERABILITY_CONTRACT_VERSION,
      createdAt: timestamp,
      evidence: [
        {
          collectedAt: timestamp,
          digest: null,
          kind: "verification",
          source: "manual-review",
          uri: null,
        },
      ],
      expiresAt: "2026-07-19T19:00:00Z",
      id: "vex-fixture-not-affected",
      justification: "scanner_identification_incorrect",
      productId: "deployment-1",
      reviewedAt: timestamp,
      statement: "The scanner matched the wrong deployed component.",
      status: "not_affected",
      vulnerabilityId: "CVE-2026-0001",
    };
    const inventory = [
      {
        asset: {
          contract: VULNERABILITY_CONTRACT_VERSION,
          criticality: "high" as const,
          environment: "production" as const,
          id: "deployment-1",
          kind: "deployment" as const,
          labels: {},
          name: "client-web",
          tenantId: "tenant-1",
          version: "release-1",
        },
        components: [],
      },
    ];
    const stores = {
      applications: {
        get: async (_tenantId: string, findingId: string) =>
          applications.get(findingId) ?? null,
        save: async (application: VexFindingApplication) => {
          applications.set(application.findingId, application);
        },
        saveMany: async (values: readonly VexFindingApplication[]) => {
          for (const value of values) applications.set(value.findingId, value);
        },
      },
      decisionStore: {
        get: async (_tenantId: string, decisionId: string) =>
          decisions.get(decisionId) ?? null,
        list: async () => [...decisions.values()],
        save: async (_tenantId: string, value: VexDecision) => {
          decisions.set(value.id, value);
        },
        saveMany: async (_tenantId: string, values: readonly VexDecision[]) => {
          for (const value of values) decisions.set(value.id, value);
        },
      },
      findings: {
        get: async (_tenantId: string, findingId: string) =>
          findings.get(findingId) ?? null,
        list: async () => [...findings.values()],
        save: async (value: ManagedVulnerabilityFinding) => {
          findings.set(value.id, value);
        },
        saveMany: async (values: readonly ManagedVulnerabilityFinding[]) => {
          for (const value of values) findings.set(value.id, value);
        },
      },
    };
    const applied = await reconcileVulnerabilityVex({
      ...stores,
      decisions: [{ decision, tenantId: "tenant-1" }],
      inventory,
      reconciledAt: timestamp,
    });
    expect(applied).toMatchObject({ applied: 1, falsePositives: 1 });
    expect(findings.get(finding.id)?.status).toBe("false_positive");

    const expiredAt = "2026-07-20T19:00:00Z";
    findings.set(finding.id, {
      ...findings.get(finding.id)!,
      lastSeenAt: expiredAt,
    });
    const expired = await reconcileVulnerabilityVex({
      ...stores,
      decisions: [{ decision, tenantId: "tenant-1" }],
      inventory,
      reconciledAt: expiredAt,
    });
    expect(expired).toMatchObject({ ended: 1, expired: 1 });
    expect(findings.get(finding.id)?.status).toBe("reopened");
  });
});

describe("vulnerability remediation reconciliation", () => {
  test("creates drafts and closes only after matching deployment and clean inventory", async () => {
    const managed: ManagedVulnerabilityFinding = {
      assetId: "deployment-1",
      componentId: "fixture-component",
      contract: VULNERABILITY_CONTRACT_VERSION,
      firstSeenAt: timestamp,
      id: `vuln_${"c".repeat(64)}`,
      lastSeenAt: timestamp,
      observationIds: ["observation-1"],
      severity: "high",
      status: "confirmed",
      tenantId: "tenant-1",
      vulnerabilityIds: ["CVE-2026-0001"],
    };
    const findings = new Map([[managed.id, managed]]);
    const plans = new Map<string, RemediationPlan>();
    const executions = new Map<string, RemediationExecution>();
    const verifications = new Map<string, RemediationVerification>();
    const inventory = [
      {
        asset: {
          contract: VULNERABILITY_CONTRACT_VERSION,
          criticality: "high" as const,
          environment: "production" as const,
          id: "deployment-1",
          kind: "deployment" as const,
          labels: {},
          name: "client-web",
          tenantId: "tenant-1",
          version: "release-1",
        },
        components: [],
      },
    ];
    const findingStore = {
      get: async (_tenantId: string, id: string) => findings.get(id) ?? null,
      list: async () => [...findings.values()],
      save: async (finding: ManagedVulnerabilityFinding) => {
        findings.set(finding.id, finding);
      },
      saveMany: async (values: readonly ManagedVulnerabilityFinding[]) => {
        for (const finding of values) findings.set(finding.id, finding);
      },
    };
    const planStore = {
      get: async (_tenantId: string, id: string) => plans.get(id) ?? null,
      list: async (filter: { status?: RemediationPlan["status"] }) =>
        [...plans.values()].filter(
          (plan) => !filter.status || plan.status === filter.status,
        ),
      save: async (_tenantId: string, plan: RemediationPlan) => {
        plans.set(plan.id, plan);
      },
    };
    const executionStore = {
      get: async (_tenantId: string, id: string) => executions.get(id) ?? null,
      list: async (_tenantId: string, planId: string) =>
        [...executions.values()].filter(
          (execution) => execution.planId === planId,
        ),
      save: async (_tenantId: string, execution: RemediationExecution) => {
        executions.set(execution.id, execution);
      },
    };
    const verificationStore = {
      get: async (_tenantId: string, id: string) =>
        verifications.get(id) ?? null,
      list: async (_tenantId: string, executionId: string) =>
        [...verifications.values()].filter(
          (verification) => verification.executionId === executionId,
        ),
      save: async (
        _tenantId: string,
        verification: RemediationVerification,
      ) => {
        verifications.set(verification.id, verification);
      },
    };
    const drafted = await createVulnerabilityRemediationDrafts({
      createdAt: timestamp,
      findings: findingStore,
      inventory,
      plans: planStore,
    });
    expect(drafted.created).toBe(1);
    const [draft] = plans.values();
    plans.set(draft!.id, {
      ...draft!,
      actions: draft!.actions.map((action) => ({
        ...action,
        toVersion: "release-2",
      })),
      approvedAt: "2026-07-18T19:30:00Z",
      approvedBy: "operator-1",
      status: "approved",
    });
    findings.set(managed.id, { ...managed, status: "remediation_planned" });
    const mismatched = await reconcileVulnerabilityRemediation({
      executions: executionStore,
      findings: findingStore,
      inventory,
      observedAt: "2026-07-18T20:30:00Z",
      plans: planStore,
      verifications: verificationStore,
      deployments: async () => ({
        activatedAt: "2026-07-18T20:00:00Z",
        assetId: "deployment-1",
        releaseId: "release-3",
      }),
    });
    expect(mismatched.executed).toBe(0);
    expect(findings.get(managed.id)?.status).toBe("remediation_planned");
    const result = await reconcileVulnerabilityRemediation({
      executions: executionStore,
      findings: findingStore,
      inventory,
      observedAt: "2026-07-18T21:00:00Z",
      plans: planStore,
      verifications: verificationStore,
      deployments: async () => ({
        activatedAt: "2026-07-18T20:00:00Z",
        assetId: "deployment-1",
        releaseId: "release-2",
      }),
    });

    expect(result).toEqual({ executed: 1, failed: 0, fixed: 1, verified: 1 });
    expect(findings.get(managed.id)?.status).toBe("fixed");
    expect([...verifications.values()][0]?.status).toBe("passed");
  });
});

describe("vulnerability inventory persistence", () => {
  test("persists correlated findings and their observations by tenant", async () => {
    const savedFindings: ManagedVulnerabilityFinding[] = [];
    const savedObservations: VulnerabilityObservation[] = [];
    const vulnerableAdvisory: VulnerabilityAdvisory = {
      ...advisory,
      affected: [
        {
          package: { ecosystem: "npm", name: "fixture", purl: null },
          ranges: [],
          versions: ["1.0.0"],
        },
      ],
      severity: [
        {
          score: 9.8,
          system: "cvss-v3",
          value: "critical",
          vector: null,
        },
      ],
    };
    const result = await correlateVulnerabilityIntelligenceInventory({
      advisories: [vulnerableAdvisory],
      findings: {
        get: async () => null,
        list: async () => savedFindings,
        save: async (finding) => {
          savedFindings.push(finding);
        },
        saveMany: async (findings) => {
          savedFindings.push(...findings);
        },
      },
      inventory: [
        {
          asset: {
            contract: VULNERABILITY_CONTRACT_VERSION,
            criticality: "high",
            environment: "production",
            id: "deployment-1",
            kind: "deployment",
            labels: {},
            name: "client-web",
            tenantId: "tenant-1",
            version: "release-1",
          },
          components: [
            {
              contract: VULNERABILITY_CONTRACT_VERSION,
              id: "fixture-component",
              identity: {
                ecosystem: "npm",
                name: "fixture",
                namespace: null,
                purl: "pkg:npm/fixture@1.0.0",
                version: "1.0.0",
              },
              licenses: [],
              locations: [],
              properties: {},
            },
          ],
        },
      ],
      observations: {
        get: async () => null,
        list: async () => savedObservations,
        save: async (_tenantId, observation) => {
          savedObservations.push(observation);
        },
        saveMany: async (_tenantId, observations) => {
          savedObservations.push(...observations);
        },
      },
      observedAt: timestamp,
    });

    expect(result).toMatchObject({
      assets: 1,
      findings: 1,
      observations: 1,
      resolved: 0,
      unknown: 0,
    });
    expect(savedFindings[0]?.severity).toBe("critical");
    expect(savedFindings[0]?.observationIds[0]).toBe(savedObservations[0]?.id);
  });
});

describe("vulnerability risk persistence", () => {
  test("joins finding CVEs to KEV and EPSS and persists explainable priority", async () => {
    const assessments: VulnerabilityRiskAssessment[] = [];
    const managedFinding: ManagedVulnerabilityFinding = {
      assetId: "deployment-1",
      componentId: "fixture-component",
      contract: VULNERABILITY_CONTRACT_VERSION,
      firstSeenAt: timestamp,
      id: `vuln_${"a".repeat(64)}`,
      lastSeenAt: timestamp,
      observationIds: ["observation-1"],
      severity: "high",
      status: "confirmed",
      tenantId: "tenant-1",
      vulnerabilityIds: ["CVE-2026-0001"],
    };
    const result = await prioritizeVulnerabilityIntelligence({
      assessedAt: timestamp,
      epss: [epss],
      findings: {
        get: async () => managedFinding,
        list: async () => [managedFinding],
        save: async () => undefined,
        saveMany: async () => undefined,
      },
      inventory: [
        {
          asset: {
            contract: VULNERABILITY_CONTRACT_VERSION,
            criticality: "critical",
            environment: "production",
            id: "deployment-1",
            kind: "deployment",
            labels: {
              "security.fix_available": "true",
              "security.internet_exposed": "true",
              "security.reachability": "reachable",
            },
            name: "client-web",
            tenantId: "tenant-1",
            version: "release-1",
          },
          components: [],
        },
      ],
      kev: [kev],
      riskAssessments: {
        get: async () => null,
        list: async () => assessments,
        save: async (_tenantId, assessment) => {
          assessments.push(assessment);
        },
        saveMany: async (_tenantId, values) => {
          assessments.push(...values);
        },
      },
    });

    expect(result).toEqual({
      assessments: 1,
      critical: 0,
      emergency: 1,
      high: 0,
    });
    expect(assessments[0]).toMatchObject({
      epssProbability: 0.31,
      kev: true,
      priority: "emergency",
      reasons: ["kev_internet_exposed", "fix_available"],
    });
  });
});
