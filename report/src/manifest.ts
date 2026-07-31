import { defineManifest } from "@absolutejs/manifest";
import { Type } from "@sinclair/typebox";

export const manifest = defineManifest<Record<string, never>>()({
  contract: 2,
  discovery: {
    audiences: ["platform-operators", "security-teams", "auditors"],
    intents: [
      "create deterministic vulnerability reports",
      "render print-ready security evidence",
      "explain false positives and remediation status",
    ],
    keywords: [
      "vulnerabilities",
      "security-report",
      "evidence",
      "VEX",
      "PDF",
      "remediation",
    ],
    protocols: ["HTML", "SHA-256 evidence digest"],
  },
  identity: {
    accent: "#7c3aed",
    category: "operations",
    description:
      "Deterministic, evidence-backed vulnerability response reports with print-ready HTML output.",
    docsUrl: "https://github.com/absolutejs/vulnerabilities-report",
    name: "@absolutejs/vulnerabilities-report",
    tagline: "Turn vulnerability decisions into a defensible client report.",
  },
  settings: Type.Object({}),
  wiring: [],
});
