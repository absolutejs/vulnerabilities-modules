import { describe, expect, test } from "bun:test";
import { evidenceWitnessTlsFilePaths } from "../src/serverTransport";

describe("standalone witness server transport", () => {
  test("keeps plaintext transport available for a private terminating proxy", () => {
    expect(evidenceWitnessTlsFilePaths({})).toBeNull();
  });

  test("requires a complete TLS identity", () => {
    expect(() =>
      evidenceWitnessTlsFilePaths({
        EVIDENCE_WITNESS_TLS_CERT_FILE: "/run/witness/tls.crt",
      }),
    ).toThrow("must be configured together");
    expect(() =>
      evidenceWitnessTlsFilePaths({
        EVIDENCE_WITNESS_TLS_KEY_FILE: "/run/witness/tls.key",
      }),
    ).toThrow("must be configured together");
  });

  test("returns only the explicitly paired runtime paths", () => {
    expect(
      evidenceWitnessTlsFilePaths({
        EVIDENCE_WITNESS_TLS_CERT_FILE: " /run/witness/tls.crt ",
        EVIDENCE_WITNESS_TLS_KEY_FILE: " /run/witness/tls.key ",
      }),
    ).toEqual({
      cert: "/run/witness/tls.crt",
      key: "/run/witness/tls.key",
    });
  });
});
