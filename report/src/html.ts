import type {
  ReportedSecurityIssue,
  VulnerabilitySecurityReport,
} from "./contracts";

const escape = (value: string) =>
  value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");

const label = (value: string) =>
  value.replaceAll("_", " ").replace(/\b\w/gu, (value) => value.toUpperCase());

const date = (value: string | null) =>
  value === null
    ? "Not provided"
    : new Intl.DateTimeFormat("en-US", {
        dateStyle: "long",
        timeStyle: "short",
        timeZone: "UTC",
      }).format(new Date(value));

const evidenceSource = (uri: string | null) => {
  if (uri === null) return "Embedded evidence";
  try {
    const parsed = new URL(uri);
    if (parsed.protocol === "https:" || parsed.protocol === "http:")
      return `<a href="${escape(parsed.href)}">${escape(uri)}</a>`;
  } catch {
    return `<code>${escape(uri)}</code>`;
  }
  return `<code>${escape(uri)}</code>`;
};

const issueHtml = (issue: ReportedSecurityIssue) => `
<article class="issue">
  <header>
    <div><span class="issue-id">${escape(issue.id)}</span><h3>${escape(issue.title)}</h3></div>
    <span class="badge ${escape(issue.disposition)}">${escape(label(issue.disposition))}</span>
  </header>
  <dl>
    <div><dt>Assessment</dt><dd>${escape(label(issue.determination))}</dd></div>
    <div><dt>Severity</dt><dd>${escape(label(issue.severity))}${issue.score === null ? "" : ` (${issue.score.toFixed(1)})`}</dd></div>
    <div><dt>Affected surface</dt><dd>${escape(issue.affectedSurface)}</dd></div>
    <div><dt>Source reference</dt><dd>${escape(issue.sourceReference ?? "Not provided")}</dd></div>
  </dl>
  <p>${escape(issue.response)}</p>
  ${
    issue.remediation
      ? `<section class="remediation"><strong>Remediation: ${escape(label(issue.remediation.status))}</strong><span>${escape(issue.remediation.summary)}</span><span>Target release(s): ${escape(issue.remediation.targetReleaseIds.join(", ") || "None")}</span><span>Verified: ${escape(date(issue.remediation.verifiedAt))}</span></section>`
      : ""
  }
  ${
    issue.evidence.length > 0
      ? `<details><summary>Evidence (${issue.evidence.length})</summary><ul>${issue.evidence
          .map(
            (evidence) =>
              `<li><strong>${escape(label(evidence.kind))}</strong> · ${escape(evidence.source)} · ${escape(date(evidence.collectedAt))}<br>${evidenceSource(evidence.uri)}</li>`,
          )
          .join("")}</ul></details>`
      : '<p class="muted">No evidence references were attached.</p>'
  }
</article>`;

const styles = `
:root{color-scheme:light;--ink:#172033;--muted:#5f6b7a;--line:#dbe1e8;--paper:#fff;--soft:#f4f7fa;--brand:#7c3aed;--good:#087a4b;--warn:#9a5b00;--bad:#b42318}*{box-sizing:border-box}body{background:#eef1f5;color:var(--ink);font:14px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin:0}.report{background:var(--paper);box-shadow:0 18px 60px #26324720;margin:32px auto;max-width:1040px;padding:48px}.cover{border-bottom:3px solid var(--brand);padding-bottom:28px}.eyebrow{color:var(--brand);font-size:12px;font-weight:800;letter-spacing:.12em;text-transform:uppercase}h1{font-size:36px;line-height:1.1;margin:10px 0}h2{font-size:22px;margin:32px 0 14px}h3{font-size:17px;margin:2px 0}.metadata,.summary{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));margin-top:24px}.metadata div,.summary div{background:var(--soft);border:1px solid var(--line);border-radius:8px;padding:12px}.metadata span,.summary span,.issue-id,.muted{color:var(--muted);font-size:12px}.metadata strong,.summary strong{display:block;font-size:18px;margin-top:3px}.issue{border:1px solid var(--line);border-radius:10px;break-inside:avoid;margin:0 0 16px;padding:18px}.issue>header{align-items:flex-start;display:flex;gap:16px;justify-content:space-between}.badge{border:1px solid currentColor;border-radius:999px;font-size:11px;font-weight:800;padding:4px 8px;text-transform:uppercase}.remediated,.vendor_patched,.false_positive{color:var(--good)}.awaiting_verification,.remediation_planned,.remediating,.accepted_risk{color:var(--warn)}.open{color:var(--bad)}.informational{color:var(--muted)}dl{display:grid;gap:8px;grid-template-columns:repeat(2,minmax(0,1fr));margin:16px 0}dl div{border-top:1px solid var(--line);padding-top:8px}dt{color:var(--muted);font-size:11px;font-weight:700;text-transform:uppercase}dd{margin:2px 0}.remediation{background:var(--soft);border-left:3px solid var(--brand);display:grid;gap:3px;padding:12px}details{margin-top:14px}summary{cursor:pointer;font-weight:700}li{margin:8px 0}a{color:#075bc7;overflow-wrap:anywhere}code{font:12px ui-monospace,SFMono-Regular,Consolas,monospace;overflow-wrap:anywhere}.integrity{border-top:1px solid var(--line);color:var(--muted);font-size:11px;margin-top:32px;padding-top:16px;overflow-wrap:anywhere}@page{size:Letter;margin:.55in}@media print{body{background:#fff}.report{box-shadow:none;margin:0;max-width:none;padding:0}.issue{break-inside:avoid}details{display:block}details>summary{list-style:none}details[open]>summary~*{display:block}}@media(max-width:700px){.report{margin:0;padding:24px}dl{grid-template-columns:1fr}h1{font-size:28px}}
`;

export const renderVulnerabilitySecurityReportHtml = (
  report: VulnerabilitySecurityReport,
) => `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'"><title>${escape(report.title)}</title><style>${styles}</style></head>
<body><main class="report">
<section class="cover"><span class="eyebrow">Security Evidence Report</span><h1>${escape(report.title)}</h1><p>${escape(report.scope)}</p>
<section class="metadata"><div><span>Prepared for</span><strong>${escape(report.preparedFor)}</strong></div><div><span>Prepared by</span><strong>${escape(report.preparedBy)}</strong></div><div><span>Generated</span><strong>${escape(date(report.generatedAt))}</strong></div><div><span>Source</span><strong>${escape(report.source.name)}</strong></div></section></section>
<h2>Executive summary</h2><section class="summary"><div><span>Reported issues</span><strong>${report.summary.total}</strong></div><div><span>Real issues</span><strong>${report.summary.real}</strong></div><div><span>False positives</span><strong>${report.summary.falsePositives}</strong></div><div><span>Remediated</span><strong>${report.summary.remediated}</strong></div><div><span>Open</span><strong>${report.summary.open}</strong></div><div><span>Awaiting verification</span><strong>${report.summary.verificationPending}</strong></div></section>
<h2>Issue-by-issue response</h2>${report.issues.map(issueHtml).join("")}
<footer class="integrity"><strong>Evidence integrity</strong><br>Report ID: ${escape(report.reportId)}<br>Digest: <code>${escape(report.digest)}</code><br>Source assessed: ${escape(date(report.source.assessedAt))}${report.source.reference ? `<br>Source reference: ${escape(report.source.reference)}` : ""}</footer>
</main></body></html>`;
