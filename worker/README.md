# @absolutejs/vulnerabilities-worker

Continuous vulnerability intelligence orchestration for AbsoluteJS.

The package refreshes EPSS, KEV, OSV, and Ubuntu intelligence under distributed
leases; records every attempt; correlates advisories with software inventory;
applies VEX decisions; assesses risk; drafts and reconciles remediation; and
exposes scheduler, health, retry, and stage metrics.

```ts
import { createVulnerabilityIntelligenceWorker } from "@absolutejs/vulnerabilities-worker";

const worker = createVulnerabilityIntelligenceWorker({
  adapters,
  history,
  leases,
  stores,
  workerId: "security-worker-1",
});

await worker.runOnce();
console.log(worker.health());
```

Applications own their inventory source, persistence wiring, deployment evidence,
audit sink, and process lifecycle. The worker owns continuous scheduling,
distributed exclusion, retries, reconciliation ordering, events, and health.
