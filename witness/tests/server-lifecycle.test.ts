import { expect, test } from "bun:test";
import { createEvidenceWitnessShutdown } from "../src/serverLifecycle";

test("standalone witness shutdown closes HTTP and database exactly once", async () => {
  const events: string[] = [];
  const shutdown = createEvidenceWitnessShutdown({
    clearMaintenance: () => events.push("maintenance-cleared"),
    stopServer: async () => {
      events.push("server-stopped");
    },
    closeDatabase: async () => {
      events.push("database-closed");
    },
  });

  const first = shutdown();
  const second = shutdown();
  expect(second).toBe(first);
  await Promise.all([first, second]);
  expect(events).toEqual([
    "maintenance-cleared",
    "server-stopped",
    "database-closed",
  ]);
});
