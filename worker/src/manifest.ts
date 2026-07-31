import { defineImplementation, defineManifest } from "@absolutejs/manifest";
import { Type } from "@sinclair/typebox";
import type { VulnerabilityIntelligenceWorkerOptions } from "./worker";

export const manifest =
  defineManifest<VulnerabilityIntelligenceWorkerOptions>()({
    contract: 2,
    discovery: {
      audiences: ["platform-operators", "security-teams"],
      intents: [
        "refresh vulnerability intelligence continuously",
        "correlate software inventory with advisories",
        "assess vulnerability risk and reconcile remediation",
      ],
      keywords: ["vulnerabilities", "CVE", "worker", "SBOM", "VEX"],
      protocols: ["AbsoluteJS vulnerability contracts"],
    },
    identity: {
      accent: "#dc2626",
      category: "operations",
      description:
        "Continuous vulnerability feed refresh, inventory correlation, VEX, risk, remediation, health, and metrics.",
      docsUrl: "https://github.com/absolutejs/vulnerabilities-worker",
      name: "@absolutejs/vulnerabilities-worker",
      tagline: "Find and prioritize exposure before it becomes an incident.",
    },
    implements: [
      defineImplementation<VulnerabilityIntelligenceWorkerOptions>()({
        contract: "vulnerabilities/worker",
        factory: "createVulnerabilityIntelligenceWorker",
        from: "@absolutejs/vulnerabilities-worker",
        requires: {
          services: [
            {
              description:
                "Feed adapters, durable stores, distributed leases, and software inventory",
              id: "vulnerability-intelligence",
            },
          ],
        },
        settings: Type.Object({
          healthMaxAgeMs: Type.Optional(Type.Integer({ minimum: 1 })),
          intervalMs: Type.Optional(Type.Integer({ minimum: 1 })),
          leaseTtlMs: Type.Optional(Type.Integer({ minimum: 1 })),
          maxStaleMs: Type.Optional(Type.Integer({ minimum: 1 })),
          retries: Type.Optional(Type.Integer({ minimum: 0 })),
          retryDelayMs: Type.Optional(Type.Integer({ minimum: 1 })),
          tickMs: Type.Optional(Type.Integer({ minimum: 1 })),
          workerId: Type.String({ minLength: 1 }),
        }),
        title: "Continuous vulnerability intelligence worker",
        wiring: {
          code: "createVulnerabilityIntelligenceWorker(${settings})",
          imports: [
            {
              from: "@absolutejs/vulnerabilities-worker",
              names: ["createVulnerabilityIntelligenceWorker"],
            },
          ],
        },
      }),
    ],
    settings: Type.Object({}),
    wiring: [],
  });
