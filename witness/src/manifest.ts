import { defineManifest } from "@absolutejs/manifest";
import { Type } from "@sinclair/typebox";

export const manifest = defineManifest<Record<string, never>>()({
  contract: 2,
  discovery: {
    audiences: ["platform-operators", "security-teams", "auditors"],
    intents: [
      "independently witness vulnerability evidence transparency",
      "detect transparency rollback and equivocation",
      "rotate witness signing keys",
      "serve durable signed witness receipts",
    ],
    keywords: [
      "vulnerabilities",
      "witness",
      "key-transparency",
      "equivocation",
      "quorum",
      "PostgreSQL",
    ],
    protocols: ["HTTPS", "Ed25519", "PostgreSQL"],
  },
  identity: {
    accent: "#dc2626",
    category: "operations",
    description:
      "Independent durable witness service for signed vulnerability-evidence transparency logs.",
    docsUrl: "https://github.com/absolutejs/vulnerabilities-witness",
    name: "@absolutejs/vulnerabilities-witness",
    tagline: "Make evidence-log rollback and equivocation externally visible.",
  },
  settings: Type.Object({}),
  wiring: [],
});
