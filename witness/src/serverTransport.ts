export type EvidenceWitnessServerEnvironment = Readonly<
  Record<string, string | undefined>
>;

const optional = (
  environment: EvidenceWitnessServerEnvironment,
  name: string,
) => environment[name]?.trim() || null;

export const evidenceWitnessTlsFilePaths = (
  environment: EvidenceWitnessServerEnvironment = process.env,
) => {
  const cert = optional(environment, "EVIDENCE_WITNESS_TLS_CERT_FILE");
  const key = optional(environment, "EVIDENCE_WITNESS_TLS_KEY_FILE");
  if (Boolean(cert) !== Boolean(key))
    throw new Error(
      "EVIDENCE_WITNESS_TLS_CERT_FILE and EVIDENCE_WITNESS_TLS_KEY_FILE must be configured together",
    );

  return cert && key ? { cert, key } : null;
};
