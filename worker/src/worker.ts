import { createHash } from "node:crypto";
import {
  createWakeScheduler,
  type WakeSchedulerMetrics,
} from "@absolutejs/queue";
import {
  syncFeedRecorded,
  type FeedAdapter,
  type FeedSnapshotStore,
  type FeedSyncResult,
  type FeedSyncRun,
  type FeedSyncRunStore,
  type ManagedFindingStore,
  type RemediationExecutionStore,
  type RemediationPlanStore,
  type RemediationVerificationStore,
  type VulnerabilityObservationStore,
  type VulnerabilityRiskAssessmentStore,
  type VexDecisionStore,
  type VexFindingApplicationStore,
} from "@absolutejs/vulnerabilities";
import type { FeedLeaseStore } from "@absolutejs/vulnerabilities-postgres";
import {
  correlateVulnerabilityIntelligenceInventory,
  createVulnerabilityRemediationDrafts,
  prioritizeVulnerabilityIntelligence,
  reconcileVulnerabilityRemediation,
  reconcileVulnerabilityVex,
  type VulnerabilityIntelligenceAdapters,
  type VulnerabilityInventoryTarget,
  type VulnerabilityIntelligenceStores,
  type VulnerabilityRemediationDeploymentProvider,
  type VulnerabilityVexConfiguration,
} from "./intelligence";

const DEFAULT_INTERVAL_MS = 3_600_000;
const DEFAULT_LEASE_TTL_MINUTES = 15;
const DEFAULT_MAX_STALE_HOURS = 24;
const DEFAULT_RETRIES = 2;
const DEFAULT_RETRY_DELAY_MS = 2_000;
const DEFAULT_TICK_MS = 30_000;
const HEALTH_INTERVAL_MULTIPLIER = 2;
const HOUR_MS = 3_600_000;
const MINUTE_MS = 60_000;
const DEFAULT_LEASE_TTL_MS = DEFAULT_LEASE_TTL_MINUTES * MINUTE_MS;
const DEFAULT_MAX_STALE_MS = DEFAULT_MAX_STALE_HOURS * HOUR_MS;

export type VulnerabilityFeedKey = keyof VulnerabilityIntelligenceAdapters;
type WorkerFeedStatus =
  | FeedSyncResult<unknown>["status"]
  | "lease_skipped"
  | "worker_failed";

export type VulnerabilityIntelligenceWorkerEvent =
  | {
      kind:
        | "vulnerability.inventory.load_failed"
        | "vulnerability.inventory.loaded";
      metadata: {
        added: number;
        changed: number;
        error: string | null;
        removed: number;
        revision: string | null;
        source: string | null;
        targets: number;
      };
    }
  | {
      kind:
        | "vulnerability.feed.failed"
        | "vulnerability.feed.lease_skipped"
        | "vulnerability.feed.synced";
      metadata: {
        attempt: number;
        error: string | null;
        feed: VulnerabilityFeedKey;
        records: number;
        status: WorkerFeedStatus;
      };
    }
  | {
      kind:
        | "vulnerability.inventory.correlated"
        | "vulnerability.inventory.failed";
      metadata: {
        assets: number;
        error: string | null;
        findings: number;
        observations: number;
        resolved: number;
        unknown: number;
      };
    }
  | {
      kind: "vulnerability.risk.assessed" | "vulnerability.risk.failed";
      metadata: {
        assessments: number;
        critical: number;
        emergency: number;
        error: string | null;
        high: number;
      };
    }
  | {
      kind: "vulnerability.vex.failed" | "vulnerability.vex.reconciled";
      metadata: {
        applied: number;
        ended: number;
        error: string | null;
        expired: number;
        falsePositives: number;
        fixed: number;
        invalid: number;
      };
    }
  | {
      kind:
        | "vulnerability.remediation.failed"
        | "vulnerability.remediation.reconciled";
      metadata: {
        created: number;
        error: string | null;
        executed: number;
        failed: number;
        fixed: number;
        verified: number;
      };
    };

export type VulnerabilityFeedWorkerMetrics = {
  attempts: number;
  failures: number;
  lastError: string | null;
  lastRecords: number;
  lastRunAt: string | null;
  lastStatus: WorkerFeedStatus | null;
  retries: number;
  successes: number;
};

export type VulnerabilityIntelligenceWorkerMetrics = {
  correlation: {
    assets: number;
    failures: number;
    findings: number;
    lastError: string | null;
    lastRunAt: string | null;
    observations: number;
    resolved: number;
    unknown: number;
  };
  feeds: Record<VulnerabilityFeedKey, VulnerabilityFeedWorkerMetrics>;
  inventory: {
    added: number;
    changed: number;
    failures: number;
    lastError: string | null;
    lastLoadedAt: string | null;
    lastRevision: string | null;
    removed: number;
    source: string | null;
    targets: number;
  };
  leaseSkips: number;
  overlapSkips: number;
  risk: {
    assessments: number;
    critical: number;
    emergency: number;
    failures: number;
    high: number;
    lastError: string | null;
    lastRunAt: string | null;
  };
  remediation: {
    created: number;
    executed: number;
    failed: number;
    failures: number;
    fixed: number;
    lastError: string | null;
    lastRunAt: string | null;
    verified: number;
  };
  vex: {
    applied: number;
    ended: number;
    expired: number;
    failures: number;
    falsePositives: number;
    fixed: number;
    invalid: number;
    lastError: string | null;
    lastRunAt: string | null;
  };
  scheduler: WakeSchedulerMetrics;
  workerFailures: number;
};

type VulnerabilityIntelligenceWorkerState = Omit<
  VulnerabilityIntelligenceWorkerMetrics,
  "scheduler"
>;

export type VulnerabilityIntelligenceHealth = {
  feeds: Record<
    VulnerabilityFeedKey,
    {
      ageMs: number | null;
      error: string | null;
      status: WorkerFeedStatus | null;
    }
  >;
  status: "blocked" | "degraded" | "passed";
};

export type VulnerabilityInventorySnapshot = {
  capturedAt: string;
  revision: string;
  source: string;
  targets: readonly VulnerabilityInventoryTarget[];
};

export type VulnerabilityInventoryProvider = {
  load: () => Promise<VulnerabilityInventorySnapshot>;
};

export type VulnerabilityIntelligenceWorkerOptions = {
  adapters: VulnerabilityIntelligenceAdapters;
  clock?: () => Date;
  healthMaxAgeMs?: number;
  history: FeedSyncRunStore;
  inventory?: readonly VulnerabilityInventoryTarget[];
  inventoryProvider?: VulnerabilityInventoryProvider;
  inventoryAdapters?: (
    inventory: readonly VulnerabilityInventoryTarget[],
  ) => VulnerabilityIntelligenceAdapters;
  intervalMs?: number;
  leaseTtlMs?: number;
  leases: FeedLeaseStore;
  maxStaleMs?: number;
  findings?: ManagedFindingStore;
  onError?: (error: unknown, feed: VulnerabilityFeedKey) => void;
  onEvent?: (
    event: VulnerabilityIntelligenceWorkerEvent,
  ) => Promise<void> | void;
  retries?: number;
  retryDelayMs?: number;
  riskAssessments?: VulnerabilityRiskAssessmentStore;
  remediationDeployments?: VulnerabilityRemediationDeploymentProvider;
  remediationExecutions?: RemediationExecutionStore;
  remediationPlans?: RemediationPlanStore;
  remediationVerifications?: RemediationVerificationStore;
  observations?: VulnerabilityObservationStore;
  sleep?: (milliseconds: number) => Promise<void>;
  stores: VulnerabilityIntelligenceStores;
  tickMs?: number;
  vex?: readonly VulnerabilityVexConfiguration[];
  vexApplications?: VexFindingApplicationStore;
  vexDecisions?: VexDecisionStore;
  workerId: string;
};

type FeedRefreshOutput = {
  attempts: number;
  error: string | null;
  feed: VulnerabilityFeedKey;
  records: number;
  run: FeedSyncRun | null;
  status: WorkerFeedStatus;
};

const positiveInteger = (value: number, label: string) => {
  if (!Number.isSafeInteger(value) || value <= 0)
    throw new Error(`${label} must be a positive integer`);

  return value;
};

const retryCount = (value: number) => {
  if (!Number.isSafeInteger(value) || value < 0)
    throw new Error("Vulnerability retries must be a non-negative integer");

  return value;
};

const EMPTY_FEED_METRICS: VulnerabilityFeedWorkerMetrics = {
  attempts: 0,
  failures: 0,
  lastError: null,
  lastRecords: 0,
  lastRunAt: null,
  lastStatus: null,
  retries: 0,
  successes: 0,
};

const eventKind = (status: WorkerFeedStatus) => {
  if (status === "lease_skipped")
    return "vulnerability.feed.lease_skipped" as const;
  if (status === "failed" || status === "stale" || status === "worker_failed")
    return "vulnerability.feed.failed" as const;

  return "vulnerability.feed.synced" as const;
};

const inventoryFingerprint = (target: VulnerabilityInventoryTarget) =>
  createHash("sha256")
    .update(
      JSON.stringify({
        asset: target.asset,
        components: target.components,
        evidence: target.evidence
          ? {
              digest: target.evidence.digest,
              source: target.evidence.source,
              uri: target.evidence.uri,
            }
          : null,
      }),
    )
    .digest("hex");

const validateInventorySnapshot = (
  snapshot: VulnerabilityInventorySnapshot,
) => {
  if (!snapshot.source.trim())
    throw new Error("Inventory snapshot source is required");
  if (!snapshot.revision.trim())
    throw new Error("Inventory snapshot revision is required");
  if (Number.isNaN(Date.parse(snapshot.capturedAt)))
    throw new Error("Inventory snapshot capturedAt must be a timestamp");
  const assetIds = new Set<string>();
  for (const target of snapshot.targets) {
    if (assetIds.has(target.asset.id))
      throw new Error(`Inventory snapshot repeats asset ${target.asset.id}`);
    assetIds.add(target.asset.id);
    if (target.evidence?.kind !== "inventory")
      throw new Error(
        `Inventory snapshot evidence for ${target.asset.id} must have kind inventory`,
      );
  }

  return snapshot;
};

export const createVulnerabilityIntelligenceWorker = (
  options: VulnerabilityIntelligenceWorkerOptions,
) => {
  const clock = options.clock ?? (() => new Date());
  const intervalMs = positiveInteger(
    options.intervalMs ?? DEFAULT_INTERVAL_MS,
    "Vulnerability intervalMs",
  );
  const leaseTtlMs = positiveInteger(
    options.leaseTtlMs ?? DEFAULT_LEASE_TTL_MS,
    "Vulnerability leaseTtlMs",
  );
  const maxStaleMs = positiveInteger(
    options.maxStaleMs ?? DEFAULT_MAX_STALE_MS,
    "Vulnerability maxStaleMs",
  );
  const retries = retryCount(options.retries ?? DEFAULT_RETRIES);
  const retryDelayMs = positiveInteger(
    options.retryDelayMs ?? DEFAULT_RETRY_DELAY_MS,
    "Vulnerability retryDelayMs",
  );
  const healthMaxAgeMs = positiveInteger(
    options.healthMaxAgeMs ?? intervalMs * HEALTH_INTERVAL_MULTIPLIER,
    "Vulnerability healthMaxAgeMs",
  );
  const sleep =
    options.sleep ??
    ((milliseconds: number) =>
      new Promise<void>((resolve) => setTimeout(resolve, milliseconds)));
  const workerId = options.workerId.trim();
  if (!workerId) throw new Error("Vulnerability workerId is required");
  if (options.inventory && options.inventoryProvider)
    throw new Error(
      "Vulnerability inventory and inventoryProvider are mutually exclusive",
    );
  const state: VulnerabilityIntelligenceWorkerState = {
    correlation: {
      assets: 0,
      failures: 0,
      findings: 0,
      lastError: null,
      lastRunAt: null,
      observations: 0,
      resolved: 0,
      unknown: 0,
    },
    feeds: {
      epss: structuredClone(EMPTY_FEED_METRICS),
      kev: structuredClone(EMPTY_FEED_METRICS),
      osv: structuredClone(EMPTY_FEED_METRICS),
      ubuntu: structuredClone(EMPTY_FEED_METRICS),
    },
    inventory: {
      added: 0,
      changed: 0,
      failures: 0,
      lastError: null,
      lastLoadedAt: null,
      lastRevision: null,
      removed: 0,
      source: null,
      targets: options.inventory?.length ?? 0,
    },
    leaseSkips: 0,
    overlapSkips: 0,
    remediation: {
      created: 0,
      executed: 0,
      failed: 0,
      failures: 0,
      fixed: 0,
      lastError: null,
      lastRunAt: null,
      verified: 0,
    },
    risk: {
      assessments: 0,
      critical: 0,
      emergency: 0,
      failures: 0,
      high: 0,
      lastError: null,
      lastRunAt: null,
    },
    vex: {
      applied: 0,
      ended: 0,
      expired: 0,
      failures: 0,
      falsePositives: 0,
      fixed: 0,
      invalid: 0,
      lastError: null,
      lastRunAt: null,
    },
    workerFailures: 0,
  };

  const refreshVex = async (
    inventory: readonly VulnerabilityInventoryTarget[],
    reconciledAt: string,
  ) => {
    if (
      !options.findings ||
      !inventory.length ||
      !options.vexApplications ||
      !options.vexDecisions
    )
      return true;
    try {
      const result = await reconcileVulnerabilityVex({
        applications: options.vexApplications,
        decisions: options.vex ?? [],
        decisionStore: options.vexDecisions,
        findings: options.findings,
        inventory,
        reconciledAt,
      });
      Object.assign(state.vex, {
        ...result,
        lastError: null,
        lastRunAt: reconciledAt,
      });
      await options.onEvent?.({
        kind: "vulnerability.vex.reconciled",
        metadata: { ...result, error: null },
      });

      return true;
    } catch (error) {
      state.vex.failures += 1;
      state.vex.lastError =
        error instanceof Error ? error.message : "VEX reconciliation failed";
      options.onError?.(error, "osv");
      await options.onEvent?.({
        kind: "vulnerability.vex.failed",
        metadata: {
          applied: 0,
          ended: 0,
          error: state.vex.lastError,
          expired: 0,
          falsePositives: 0,
          fixed: 0,
          invalid: 0,
        },
      });

      return false;
    }
  };

  const refreshRemediation = async (
    inventory: readonly VulnerabilityInventoryTarget[],
    observedAt: string,
  ) => {
    if (
      !options.findings ||
      !inventory.length ||
      !options.remediationDeployments ||
      !options.remediationExecutions ||
      !options.remediationPlans ||
      !options.remediationVerifications
    )
      return;
    try {
      const drafts = await createVulnerabilityRemediationDrafts({
        createdAt: observedAt,
        findings: options.findings,
        inventory,
        plans: options.remediationPlans,
      });
      const reconciled = await reconcileVulnerabilityRemediation({
        deployments: options.remediationDeployments,
        executions: options.remediationExecutions,
        findings: options.findings,
        inventory,
        observedAt,
        plans: options.remediationPlans,
        verifications: options.remediationVerifications,
      });
      const result: typeof drafts & typeof reconciled = {
        ...drafts,
        ...reconciled,
      };
      Object.assign(state.remediation, {
        ...result,
        lastError: null,
        lastRunAt: observedAt,
      });
      await options.onEvent?.({
        kind: "vulnerability.remediation.reconciled",
        metadata: { ...result, error: null },
      });
    } catch (error) {
      state.remediation.failures += 1;
      state.remediation.lastError =
        error instanceof Error
          ? error.message
          : "Remediation reconciliation failed";
      options.onError?.(error, "osv");
      await options.onEvent?.({
        kind: "vulnerability.remediation.failed",
        metadata: {
          created: 0,
          error: state.remediation.lastError,
          executed: 0,
          failed: 0,
          fixed: 0,
          verified: 0,
        },
      });
    }
  };

  const refreshRisk = async (
    feeds: Record<VulnerabilityFeedKey, FeedRefreshOutput>,
    inventory: readonly VulnerabilityInventoryTarget[],
    assessedAt: string,
  ) => {
    if (!options.findings || !inventory.length || !options.riskAssessments)
      return;
    if (
      !["updated", "not_modified"].includes(feeds.epss.status) ||
      !["updated", "not_modified"].includes(feeds.kev.status)
    )
      return;
    try {
      const [epss, kev] = await Promise.all([
        options.stores.epss.load(options.adapters.epss.descriptor.id),
        options.stores.kev.load(options.adapters.kev.descriptor.id),
      ]);
      if (!epss || !kev)
        throw new Error("Vulnerability risk snapshots are unavailable");
      const result = await prioritizeVulnerabilityIntelligence({
        assessedAt,
        epss: epss.records.map(({ value }) => value),
        findings: options.findings,
        inventory,
        kev: kev.records.map(({ value }) => value),
        riskAssessments: options.riskAssessments,
      });
      Object.assign(state.risk, {
        ...result,
        lastError: null,
        lastRunAt: assessedAt,
      });
      await options.onEvent?.({
        kind: "vulnerability.risk.assessed",
        metadata: { ...result, error: null },
      });
    } catch (error) {
      state.risk.failures += 1;
      state.risk.lastError =
        error instanceof Error ? error.message : "Risk assessment failed";
      options.onError?.(error, "epss");
      await options.onEvent?.({
        kind: "vulnerability.risk.failed",
        metadata: {
          assessments: 0,
          critical: 0,
          emergency: 0,
          error: state.risk.lastError,
          high: 0,
        },
      });
    }
  };

  const refreshInventory = async (
    feeds: Record<VulnerabilityFeedKey, FeedRefreshOutput>,
    inventory: readonly VulnerabilityInventoryTarget[],
    reconciliationInventory: readonly VulnerabilityInventoryTarget[] = inventory,
  ) => {
    if (
      !options.findings ||
      !options.observations ||
      !reconciliationInventory.length
    )
      return;
    if (
      !["updated", "not_modified"].includes(feeds.osv.status) ||
      !["updated", "not_modified"].includes(feeds.ubuntu.status)
    )
      return;
    try {
      const [osv, ubuntu] = await Promise.all([
        options.stores.osv.load(options.adapters.osv.descriptor.id),
        options.stores.ubuntu.load(options.adapters.ubuntu.descriptor.id),
      ]);
      if (!osv || !ubuntu)
        throw new Error("Vulnerability advisory snapshots are unavailable");
      const observedAt = clock().toISOString();
      const result = await correlateVulnerabilityIntelligenceInventory({
        advisories: [
          ...osv.records.map(({ value }) => value),
          ...ubuntu.records.map(({ value }) => value),
        ],
        findings: options.findings,
        inventory: reconciliationInventory,
        observations: options.observations,
        observedAt,
      });
      Object.assign(state.correlation, {
        ...result,
        lastError: null,
        lastRunAt: observedAt,
      });
      await options.onEvent?.({
        kind: "vulnerability.inventory.correlated",
        metadata: { ...result, error: null },
      });
      if (!(await refreshVex(inventory, observedAt))) return;
      await refreshRemediation(inventory, observedAt);
      await refreshRisk(feeds, inventory, observedAt);
    } catch (error) {
      state.correlation.failures += 1;
      state.correlation.lastError =
        error instanceof Error ? error.message : "Correlation failed";
      options.onError?.(error, "osv");
      await options.onEvent?.({
        kind: "vulnerability.inventory.failed",
        metadata: {
          assets: reconciliationInventory.length,
          error: state.correlation.lastError,
          findings: 0,
          observations: 0,
          resolved: 0,
          unknown: 0,
        },
      });
    }
  };

  const emit = async (
    feed: VulnerabilityFeedKey,
    attempt: number,
    status: WorkerFeedStatus,
    error: string | null,
    records: number,
  ) =>
    options.onEvent?.({
      kind: eventKind(status),
      metadata: { attempt, error, feed, records, status },
    });

  const refreshFeed = async <T>(
    feed: VulnerabilityFeedKey,
    adapter: FeedAdapter<T>,
    store: FeedSnapshotStore<T>,
  ) => {
    const feedMetrics = state.feeds[feed];
    const acquired = await options.leases.acquire({
      feedId: adapter.descriptor.id,
      now: clock(),
      ownerId: workerId,
      ttlMs: leaseTtlMs,
    });
    if (!acquired) {
      state.leaseSkips += 1;
      feedMetrics.lastStatus = "lease_skipped";
      await emit(feed, 0, "lease_skipped", null, 0);

      return {
        attempts: 0,
        error: null,
        feed,
        records: 0,
        run: null,
        status: "lease_skipped",
      } satisfies FeedRefreshOutput;
    }
    let last: FeedRefreshOutput | undefined;
    const executeAttempt: (attempt: number) => Promise<FeedRefreshOutput> =
      async function attemptFeed(attempt) {
        feedMetrics.attempts += 1;
        const output = await syncFeedRecorded({
          adapter,
          clock,
          history: options.history,
          maxStaleMs,
          now: clock().getTime(),
          store,
        });
        const records = output.result.snapshot?.records.length ?? 0;
        const failed =
          output.result.status === "failed" || output.result.status === "stale";
        feedMetrics.lastError = output.result.error;
        feedMetrics.lastRecords = records;
        feedMetrics.lastRunAt = output.run.completedAt;
        feedMetrics.lastStatus = output.result.status;
        if (failed) feedMetrics.failures += 1;
        else feedMetrics.successes += 1;
        await emit(
          feed,
          attempt,
          output.result.status,
          output.result.error,
          records,
        );
        last = {
          attempts: attempt,
          error: output.result.error,
          feed,
          records,
          run: output.run,
          status: output.result.status,
        };
        if (!failed || attempt > retries) return last;
        feedMetrics.retries += 1;
        await sleep(retryDelayMs * attempt);

        return attemptFeed(attempt + 1);
      };
    try {
      return await executeAttempt(1);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Unknown worker failure";
      state.workerFailures += 1;
      feedMetrics.failures += 1;
      feedMetrics.lastError = message;
      feedMetrics.lastRunAt = clock().toISOString();
      feedMetrics.lastStatus = "worker_failed";
      options.onError?.(error, feed);
      await emit(feed, last?.attempts ?? 0, "worker_failed", message, 0);

      return {
        attempts: last?.attempts ?? 0,
        error: message,
        feed,
        records: 0,
        run: last?.run ?? null,
        status: "worker_failed",
      } satisfies FeedRefreshOutput;
    } finally {
      await options.leases.release(adapter.descriptor.id, workerId);
    }
  };

  let previousInventory = new Map<string, VulnerabilityInventoryTarget>();
  const loadInventory = async () => {
    if (!options.inventoryProvider)
      return {
        current: options.inventory ?? [],
        reconciliation: options.inventory ?? [],
      };
    try {
      const snapshot = validateInventorySnapshot(
        await options.inventoryProvider.load(),
      );
      const current = new Map(
        snapshot.targets.map((target) => [target.asset.id, target]),
      );
      let added = 0;
      let changed = 0;
      for (const [assetId, target] of current) {
        const prior = previousInventory.get(assetId);
        if (!prior) added += 1;
        else if (inventoryFingerprint(prior) !== inventoryFingerprint(target))
          changed += 1;
      }
      const removed = [...previousInventory.keys()].filter(
        (assetId) => !current.has(assetId),
      );
      const retired = removed.map((assetId) => ({
        ...previousInventory.get(assetId)!,
        components: [],
      }));
      previousInventory = current;
      Object.assign(state.inventory, {
        added,
        changed,
        lastError: null,
        lastLoadedAt: clock().toISOString(),
        lastRevision: snapshot.revision,
        removed: removed.length,
        source: snapshot.source,
        targets: snapshot.targets.length,
      });
      await options.onEvent?.({
        kind: "vulnerability.inventory.loaded",
        metadata: {
          added,
          changed,
          error: null,
          removed: removed.length,
          revision: snapshot.revision,
          source: snapshot.source,
          targets: snapshot.targets.length,
        },
      });

      return {
        current: snapshot.targets,
        reconciliation: [...snapshot.targets, ...retired],
      };
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Inventory load failed";
      state.inventory.failures += 1;
      state.inventory.lastError = message;
      options.onError?.(error, "osv");
      await options.onEvent?.({
        kind: "vulnerability.inventory.load_failed",
        metadata: {
          added: 0,
          changed: 0,
          error: message,
          removed: 0,
          revision: null,
          source: null,
          targets: 0,
        },
      });

      return null;
    }
  };

  let activeRun: Promise<
    Record<VulnerabilityFeedKey, FeedRefreshOutput>
  > | null = null;
  const runOnce = () => {
    if (activeRun) {
      state.overlapSkips += 1;

      return activeRun;
    }
    activeRun = loadInventory()
      .then(async (inventory) => {
        const runAdapters =
          inventory && options.inventoryAdapters
            ? options.inventoryAdapters(inventory.current)
            : options.adapters;
        const [epss, kev, osv, ubuntu] = await Promise.all([
          refreshFeed("epss", runAdapters.epss, options.stores.epss),
          refreshFeed("kev", runAdapters.kev, options.stores.kev),
          refreshFeed("osv", runAdapters.osv, options.stores.osv),
          refreshFeed("ubuntu", runAdapters.ubuntu, options.stores.ubuntu),
        ]);
        const feeds: Record<VulnerabilityFeedKey, FeedRefreshOutput> = {
          epss,
          kev,
          osv,
          ubuntu,
        };
        if (inventory)
          await refreshInventory(
            feeds,
            inventory.current,
            inventory.reconciliation,
          );

        return feeds;
      })
      .finally(() => {
        activeRun = null;
      });

    return activeRun;
  };

  const scheduler = createWakeScheduler({
    catchUp: "once",
    entries: [
      {
        every: intervalMs,
        id: "vulnerability-intelligence-refresh",
        tenant: "control-plane",
      },
    ],
    tickMs: positiveInteger(
      options.tickMs ?? DEFAULT_TICK_MS,
      "Vulnerability tickMs",
    ),
    onError: (error) => options.onError?.(error, "osv"),
    wake: async () => {
      await runOnce();
    },
  });
  let started = false;

  return {
    runOnce,
    dispose: async () => {
      if (!started) return;
      scheduler.drain();
      await scheduler.stop();
      await activeRun;
      started = false;
    },
    health: (): VulnerabilityIntelligenceHealth => {
      const now = clock().getTime();
      const feeds = Object.fromEntries(
        (Object.keys(state.feeds) as VulnerabilityFeedKey[]).map((feed) => {
          const metrics = state.feeds[feed];
          const ageMs = metrics.lastRunAt
            ? Math.max(0, now - Date.parse(metrics.lastRunAt))
            : null;

          return [
            feed,
            {
              ageMs,
              error: metrics.lastError,
              status: metrics.lastStatus,
            },
          ];
        }),
      ) as VulnerabilityIntelligenceHealth["feeds"];
      const values = Object.values(feeds);
      const neverRan = values.every(({ status }) => status === null);
      const degraded =
        values.some(
          ({ ageMs, status }) =>
            ageMs === null ||
            ageMs > healthMaxAgeMs ||
            status === "failed" ||
            status === "stale" ||
            status === "worker_failed",
        ) ||
        state.correlation.lastError !== null ||
        state.inventory.lastError !== null ||
        state.remediation.lastError !== null ||
        state.risk.lastError !== null ||
        state.vex.lastError !== null;
      let status: VulnerabilityIntelligenceHealth["status"] = "passed";
      if (neverRan) status = "blocked";
      else if (degraded) status = "degraded";

      return {
        feeds,
        status,
      };
    },
    metrics: (): VulnerabilityIntelligenceWorkerMetrics => ({
      ...structuredClone(state),
      scheduler: scheduler.metrics(),
    }),
    start: () => {
      if (started) return;
      scheduler.start();
      started = true;
    },
  };
};
