import { Type, type Static } from "@sinclair/typebox";
import {
  EvidenceReferenceSchema,
  ISO_TIMESTAMP_PATTERN,
  VulnerabilitySeveritySchema,
} from "@absolutejs/vulnerabilities";

const TimestampSchema = Type.String({ pattern: ISO_TIMESTAMP_PATTERN });
const TextSchema = Type.String({ minLength: 1 });

export const ReportDeterminationSchema = Type.Union([
  Type.Literal("real"),
  Type.Literal("false_positive"),
  Type.Literal("informational"),
]);
export type ReportDetermination = Static<typeof ReportDeterminationSchema>;

export const ReportDispositionSchema = Type.Union([
  Type.Literal("open"),
  Type.Literal("remediation_planned"),
  Type.Literal("remediating"),
  Type.Literal("awaiting_verification"),
  Type.Literal("remediated"),
  Type.Literal("vendor_patched"),
  Type.Literal("false_positive"),
  Type.Literal("accepted_risk"),
  Type.Literal("informational"),
]);
export type ReportDisposition = Static<typeof ReportDispositionSchema>;

export const ReportedSecurityIssueSchema = Type.Object(
  {
    affectedSurface: TextSchema,
    determination: ReportDeterminationSchema,
    disposition: ReportDispositionSchema,
    evidence: Type.Array(EvidenceReferenceSchema),
    id: TextSchema,
    remediation: Type.Union([
      Type.Null(),
      Type.Object(
        {
          status: TextSchema,
          summary: TextSchema,
          targetReleaseIds: Type.Array(TextSchema, { uniqueItems: true }),
          verifiedAt: Type.Union([Type.Null(), TimestampSchema]),
        },
        { additionalProperties: false },
      ),
    ]),
    response: TextSchema,
    score: Type.Union([Type.Null(), Type.Number({ minimum: 0, maximum: 10 })]),
    severity: VulnerabilitySeveritySchema,
    sourceReference: Type.Union([Type.Null(), TextSchema]),
    title: TextSchema,
    vulnerabilityIds: Type.Array(TextSchema, { uniqueItems: true }),
  },
  { additionalProperties: false },
);
export type ReportedSecurityIssue = Static<typeof ReportedSecurityIssueSchema>;

export const VulnerabilitySecurityReportInputSchema = Type.Object(
  {
    generatedAt: TimestampSchema,
    issues: Type.Array(ReportedSecurityIssueSchema),
    preparedBy: TextSchema,
    preparedFor: TextSchema,
    reportId: TextSchema,
    scope: TextSchema,
    source: Type.Object(
      {
        assessedAt: Type.Union([Type.Null(), TimestampSchema]),
        name: TextSchema,
        reference: Type.Union([Type.Null(), TextSchema]),
      },
      { additionalProperties: false },
    ),
    title: TextSchema,
  },
  { additionalProperties: false },
);
export type VulnerabilitySecurityReportInput = Static<
  typeof VulnerabilitySecurityReportInputSchema
>;

export const VulnerabilitySecurityReportSchema = Type.Object(
  {
    ...VulnerabilitySecurityReportInputSchema.properties,
    digest: Type.String({ pattern: "^sha256:[a-f0-9]{64}$" }),
    summary: Type.Object(
      {
        falsePositives: Type.Integer({ minimum: 0 }),
        informational: Type.Integer({ minimum: 0 }),
        open: Type.Integer({ minimum: 0 }),
        real: Type.Integer({ minimum: 0 }),
        remediated: Type.Integer({ minimum: 0 }),
        total: Type.Integer({ minimum: 0 }),
        verificationPending: Type.Integer({ minimum: 0 }),
      },
      { additionalProperties: false },
    ),
  },
  { additionalProperties: false },
);
export type VulnerabilitySecurityReport = Static<
  typeof VulnerabilitySecurityReportSchema
>;
