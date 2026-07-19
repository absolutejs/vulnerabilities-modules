import {
  EVIDENCE_WITNESS_REQUEST_CONTRACT,
  type EvidenceWitnessRequest,
  type createEvidenceWitnessService,
} from "./service";
import {
  EvidenceWitnessEquivocationError,
  EvidenceWitnessRollbackError,
} from "./store";

const json = (value: unknown, status = 200) =>
  Response.json(value, {
    headers: { "cache-control": "no-store" },
    status,
  });

const bearer = (request: Request) => {
  const authorization = request.headers.get("authorization") ?? "";
  return authorization.startsWith("Bearer ")
    ? authorization.slice("Bearer ".length).trim()
    : "";
};

export const createEvidenceWitnessHttpHandler =
  (options: {
    authenticate: (token: string) => Promise<string | null>;
    service: ReturnType<typeof createEvidenceWitnessService>;
  }) =>
  async (request: Request) => {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/health")
      return json({ status: "ok" });
    if (request.method === "GET" && url.pathname === "/v1/keys")
      return json(await options.service.registry());
    if (request.method === "GET" && url.pathname === "/v1/status") {
      const subject = await options.authenticate(bearer(request));
      if (!subject) return json({ error: "unauthorized" }, 401);
      return json(await options.service.status());
    }
    if (request.method !== "POST" || url.pathname !== "/v1/checkpoints")
      return json({ error: "not_found" }, 404);
    const subject = await options.authenticate(bearer(request));
    if (!subject) return json({ error: "unauthorized" }, 401);
    try {
      const input = (await request.json()) as EvidenceWitnessRequest;
      if (input.contract !== EVIDENCE_WITNESS_REQUEST_CONTRACT)
        return json({ error: "unsupported_contract" }, 400);
      return json(await options.service.checkpoint(subject, input));
    } catch (error) {
      if (error instanceof EvidenceWitnessEquivocationError)
        return json({ error: "equivocation", message: error.message }, 409);
      if (error instanceof EvidenceWitnessRollbackError)
        return json({ error: "rollback", message: error.message }, 409);
      return json(
        {
          error: "invalid_request",
          message: error instanceof Error ? error.message : "Invalid request",
        },
        400,
      );
    }
  };
