# @absolutejs/vulnerabilities-report

Deterministic, evidence-backed security response reports for AbsoluteJS
vulnerability management. The package maps reported issues to explicit
determinations, remediation state, VEX evidence, exact deployment releases,
and later verification without coupling the report to PAAS or a PDF engine.

The HTML renderer is self-contained, contains print styles for Letter-sized
PDF output, has no scripts or external assets, escapes all report content, and
includes a SHA-256 digest over the canonical report payload.

```ts
import {
  createVulnerabilitySecurityReport,
  renderVulnerabilitySecurityReportHtml,
} from "@absolutejs/vulnerabilities-report";

const report = createVulnerabilitySecurityReport({
  generatedAt: new Date().toISOString(),
  issues,
  preparedBy: "Security Operations",
  preparedFor: "Client",
  reportId: "security-report-2026-07",
  scope: "Production web and host vulnerability posture",
  source: {
    assessedAt: "2026-07-17T20:59:48.000Z",
    name: "External vulnerability scan",
    reference: "scan-13747781",
  },
  title: "Security Remediation Response",
});

const html = renderVulnerabilitySecurityReportHtml(report);
```

Applications may create `ReportedSecurityIssue` records directly for an
external scanner report or use `createReportedIssueFromFinding` to project
AbsoluteJS managed findings, VEX decisions, remediation plans, executions,
and verification evidence into the same report format.
