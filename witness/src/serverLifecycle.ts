export type EvidenceWitnessServerLifecycle = {
  closeDatabase: () => Promise<void> | void;
  clearMaintenance: () => void;
  stopServer: () => Promise<void> | void;
};

export const createEvidenceWitnessShutdown = (
  lifecycle: EvidenceWitnessServerLifecycle,
) => {
  let shutdown: Promise<void> | null = null;
  return () => {
    shutdown ??= (async () => {
      lifecycle.clearMaintenance();
      await lifecycle.stopServer();
      await lifecycle.closeDatabase();
    })();
    return shutdown;
  };
};
