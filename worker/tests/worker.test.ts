import {
  VULNERABILITY_CONTRACT_VERSION,
  type FeedAdapter,
  type FeedSyncRun,
  type FeedSyncRunStore,
  type ManagedVulnerabilityFinding,
  type VulnerabilityObservation,
  type VulnerabilityAdvisory,
  type VulnerabilityRiskAssessment,
  type VexDecision,
  type VexFindingApplication,
} from "@absolutejs/vulnerabilities";
import type { EpssScore } from "@absolutejs/vulnerabilities-epss";
import type { KevEntry } from "@absolutejs/vulnerabilities-kev";
import type { FeedLeaseRequest } from "@absolutejs/vulnerabilities-postgres";
import { describe, expect, test } from "bun:test";
import {
  createVulnerabilityIntelligenceMemoryStores,
  type VulnerabilityIntelligenceAdapters,
  type VulnerabilityInventoryTarget,
} from "../src/intelligence";
import { createVulnerabilityIntelligenceWorker } from "../src/worker";

const timestamp = "2026-07-18T19:00:00Z";

const fixtureAdapter = <T>(
  id: string,
  value: T,
  options: { failFirst?: boolean; wait?: Promise<void> } = {},
): FeedAdapter<T> => {
  let calls = 0;

  return {
    descriptor: {
      id,
      name: `${id} fixture`,
      url: `https://security.example/${id}`,
    },
    fetch: async () => {
      calls += 1;
      if (options.wait) await options.wait;
      if (options.failFirst && calls === 1)
        throw new Error(`${id} unavailable`);

      return {
        cursor: { etag: null, lastModified: null, token: null },
        fetchedAt: timestamp,
        records: [{ id, modifiedAt: timestamp, value }],
        replaceAll: true,
        revision: "1",
        status: "updated",
      };
    },
  };
};

const epss: EpssScore = {
  cve: "CVE-2026-0001",
  date: "2026-07-18",
  percentile: 0.97,
  probability: 0.31,
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

const inventoryTarget = (
  assetId: string,
  release: string,
): VulnerabilityInventoryTarget => ({
  asset: {
    contract: VULNERABILITY_CONTRACT_VERSION,
    criticality: "high",
    environment: "production",
    id: assetId,
    kind: "deployment",
    labels: {},
    name: assetId,
    tenantId: assetId,
    version: release,
  },
  components: [],
  evidence: {
    collectedAt: timestamp,
    digest: `sha256:${"a".repeat(64)}`,
    kind: "inventory",
    source: "paas-release",
    uri: `inventory://${assetId}/${release}`,
  },
});

const adapters = (
  override: Partial<VulnerabilityIntelligenceAdapters> = {},
): VulnerabilityIntelligenceAdapters => ({
  epss: override.epss ?? fixtureAdapter("first-epss", epss),
  kev: override.kev ?? fixtureAdapter("cisa-kev", kev),
  osv: override.osv ?? fixtureAdapter("osv", advisory),
  ubuntu: override.ubuntu ?? fixtureAdapter("ubuntu", advisory),
});

const history = () => {
  const runs: FeedSyncRun[] = [];
  const store: FeedSyncRunStore = {
    append: async (run) => {
      runs.push(run);
    },
    list: async () => runs,
  };

  return { runs, store };
};

const leases = () => {
  const owners = new Map<string, string>();

  return {
    owners,
    acquire: async ({ feedId, ownerId }: FeedLeaseRequest) => {
      const owner = owners.get(feedId);
      if (owner && owner !== ownerId) return false;
      owners.set(feedId, ownerId);

      return true;
    },
    release: async (feedId: string, ownerId: string) =>
      owners.get(feedId) === ownerId && owners.delete(feedId),
  };
};

describe("vulnerability intelligence worker", () => {
  test("reloads live inventory and reports deployment drift", async () => {
    const snapshots = [
      [inventoryTarget("deployment-1", "release-1")],
      [
        inventoryTarget("deployment-1", "release-2"),
        inventoryTarget("deployment-2", "release-1"),
      ],
    ];
    let loads = 0;
    const adapterInventories: string[][] = [];
    const events: string[] = [];
    const worker = createVulnerabilityIntelligenceWorker({
      adapters: adapters(),
      history: history().store,
      inventoryProvider: {
        load: async () => ({
          capturedAt: timestamp,
          revision: `revision-${loads + 1}`,
          source: "paas-active-deployments",
          targets: snapshots[loads++] ?? snapshots.at(-1)!,
        }),
      },
      inventoryAdapters: (inventory) => {
        adapterInventories.push(
          inventory.map(({ asset }) => asset.version ?? "unknown"),
        );

        return adapters();
      },
      leases: leases(),
      retries: 0,
      stores: createVulnerabilityIntelligenceMemoryStores(),
      workerId: "worker-1",
      clock: () => new Date(timestamp),
      onEvent: ({ kind }) => {
        events.push(kind);
      },
    });

    await worker.runOnce();
    expect(worker.metrics().inventory).toMatchObject({
      added: 1,
      changed: 0,
      removed: 0,
      targets: 1,
    });
    await worker.runOnce();
    expect(loads).toBe(2);
    expect(adapterInventories).toEqual([
      ["release-1"],
      ["release-2", "release-1"],
    ]);
    expect(worker.metrics().inventory).toMatchObject({
      added: 1,
      changed: 1,
      lastRevision: "revision-2",
      removed: 0,
      targets: 2,
    });
    expect(
      events.filter((kind) => kind === "vulnerability.inventory.loaded"),
    ).toHaveLength(2);
  });

  test("degrades health when live inventory cannot be loaded", async () => {
    const worker = createVulnerabilityIntelligenceWorker({
      adapters: adapters(),
      history: history().store,
      inventoryProvider: {
        load: async () => {
          throw new Error("deployment inventory unavailable");
        },
      },
      leases: leases(),
      retries: 0,
      stores: createVulnerabilityIntelligenceMemoryStores(),
      workerId: "worker-1",
      clock: () => new Date(timestamp),
    });

    await worker.runOnce();
    expect(worker.metrics().inventory).toMatchObject({
      failures: 1,
      lastError: "deployment inventory unavailable",
    });
    expect(worker.health().status).toBe("degraded");
  });

  test("retries provider failures, records every attempt, and reports health", async () => {
    const syncHistory = history();
    const events: string[] = [];
    const worker = createVulnerabilityIntelligenceWorker({
      adapters: adapters({
        kev: fixtureAdapter("cisa-kev", kev, { failFirst: true }),
      }),
      history: syncHistory.store,
      leases: leases(),
      retries: 1,
      retryDelayMs: 1,
      stores: createVulnerabilityIntelligenceMemoryStores(),
      workerId: "worker-1",
      clock: () => new Date(timestamp),
      onEvent: ({ kind }) => {
        events.push(kind);
      },
      sleep: async () => undefined,
    });

    const result = await worker.runOnce();
    expect(result.kev.status).toBe("updated");
    expect(result.kev.attempts).toBe(2);
    expect(syncHistory.runs).toHaveLength(5);
    expect(worker.metrics().feeds.kev.retries).toBe(1);
    expect(events).toContain("vulnerability.feed.failed");
    expect(events).toContain("vulnerability.feed.synced");
    expect(worker.health().status).toBe("passed");
  });

  test("skips a feed leased by another worker without blocking others", async () => {
    const leaseStore = leases();
    leaseStore.owners.set("osv", "other-worker");
    const worker = createVulnerabilityIntelligenceWorker({
      adapters: adapters(),
      history: history().store,
      leases: leaseStore,
      retries: 0,
      stores: createVulnerabilityIntelligenceMemoryStores(),
      workerId: "worker-1",
      clock: () => new Date(timestamp),
    });

    const result = await worker.runOnce();
    expect(result.osv.status).toBe("lease_skipped");
    expect(result.ubuntu.status).toBe("updated");
    expect(worker.metrics().leaseSkips).toBe(1);
  });

  test("coalesces overlapping local refresh requests", async () => {
    let release: () => void = () => undefined;
    const wait = new Promise<void>((resolve) => {
      release = resolve;
    });
    const worker = createVulnerabilityIntelligenceWorker({
      adapters: adapters({
        osv: fixtureAdapter("osv", advisory, { wait }),
      }),
      history: history().store,
      leases: leases(),
      retries: 0,
      stores: createVulnerabilityIntelligenceMemoryStores(),
      workerId: "worker-1",
    });
    const first = worker.runOnce();
    const second = worker.runOnce();
    release();

    expect(await second).toEqual(await first);
    expect(worker.metrics().overlapSkips).toBe(1);
  });

  test("correlates fresh advisories and assesses KEV and EPSS risk", async () => {
    const vulnerable: VulnerabilityAdvisory = {
      ...advisory,
      affected: [
        {
          package: { ecosystem: "npm", name: "fixture", purl: null },
          ranges: [],
          versions: ["1.0.0"],
        },
      ],
    };
    const savedFindings = new Map<string, ManagedVulnerabilityFinding>();
    const savedObservations: VulnerabilityObservation[] = [];
    const savedAssessments: VulnerabilityRiskAssessment[] = [];
    const savedVexApplications = new Map<string, VexFindingApplication>();
    const savedVexDecisions = new Map<string, VexDecision>();
    const events: string[] = [];
    const worker = createVulnerabilityIntelligenceWorker({
      adapters: adapters({
        osv: fixtureAdapter("osv", vulnerable),
        ubuntu: fixtureAdapter("ubuntu", vulnerable),
      }),
      findings: {
        get: async (_tenantId, findingId) =>
          savedFindings.get(findingId) ?? null,
        list: async ({ assetId, tenantId }) =>
          [...savedFindings.values()].filter(
            (finding) =>
              finding.assetId === assetId && finding.tenantId === tenantId,
          ),
        save: async (finding) => {
          savedFindings.set(finding.id, finding);
        },
        saveMany: async (findings) => {
          for (const finding of findings)
            savedFindings.set(finding.id, finding);
        },
      },
      history: history().store,
      inventory: [
        {
          asset: {
            contract: VULNERABILITY_CONTRACT_VERSION,
            criticality: "high",
            environment: "production",
            id: "deployment-1",
            kind: "deployment",
            labels: {
              "security.fix_available": "true",
              "security.internet_exposed": "true",
            },
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
      leases: leases(),
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
      retries: 0,
      riskAssessments: {
        get: async () => null,
        list: async () => savedAssessments,
        save: async (_tenantId, assessment) => {
          savedAssessments.push(assessment);
        },
        saveMany: async (_tenantId, assessments) => {
          savedAssessments.push(...assessments);
        },
      },
      stores: createVulnerabilityIntelligenceMemoryStores(),
      vex: [],
      vexApplications: {
        get: async (_tenantId, findingId) =>
          savedVexApplications.get(findingId) ?? null,
        save: async (application) => {
          savedVexApplications.set(application.findingId, application);
        },
        saveMany: async (applications) => {
          for (const application of applications)
            savedVexApplications.set(application.findingId, application);
        },
      },
      vexDecisions: {
        get: async (_tenantId, decisionId) =>
          savedVexDecisions.get(decisionId) ?? null,
        list: async () => [...savedVexDecisions.values()],
        save: async (_tenantId, decision) => {
          savedVexDecisions.set(decision.id, decision);
        },
        saveMany: async (_tenantId, decisions) => {
          for (const decision of decisions)
            savedVexDecisions.set(decision.id, decision);
        },
      },
      workerId: "worker-1",
      clock: () => new Date(timestamp),
      onEvent: ({ kind }) => {
        events.push(kind);
      },
    });

    await worker.runOnce();
    expect(savedObservations).toHaveLength(1);
    expect(savedAssessments[0]?.priority).toBe("emergency");
    expect(worker.metrics().risk).toMatchObject({
      assessments: 1,
      emergency: 1,
    });
    expect(events).toContain("vulnerability.inventory.correlated");
    expect(events).toContain("vulnerability.vex.reconciled");
    expect(events).toContain("vulnerability.risk.assessed");
    expect(events.indexOf("vulnerability.vex.reconciled")).toBeLessThan(
      events.indexOf("vulnerability.risk.assessed"),
    );
  });
});
