// Turns CheckResult[] into the three output shapes keysnag produces: a human markdown report,
// raw JSON, and a copy-paste block phrased for a coding agent to act on.
import type { CheckResult, Finding, Severity } from "./types.js";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

function allFindings(results: CheckResult[]): Finding[] {
  return results.flatMap((r) => r.findings);
}

function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<
    Severity,
    number
  >;
  for (const f of findings) counts[f.severity]++;
  return counts;
}

function summaryLine(results: CheckResult[]): string {
  const findings = allFindings(results);
  const counts = countBySeverity(findings);
  const ran = results.filter((r) => r.ran).length;
  const skipped = results.filter((r) => !r.ran).length;
  const parts = SEVERITY_ORDER.filter((s) => counts[s] > 0).map(
    (s) => `${counts[s]} ${SEVERITY_LABEL[s].toLowerCase()}`,
  );
  const findingsPart = parts.length > 0 ? parts.join(", ") : "no findings";
  return `${ran} check(s) ran, ${skipped} skipped. ${findingsPart}.`;
}

export function renderMarkdown(results: CheckResult[]): string {
  const lines: string[] = [];
  lines.push("# keysnag report", "");
  lines.push(summaryLine(results), "");

  const findings = allFindings(results);
  for (const severity of SEVERITY_ORDER) {
    const group = findings.filter((f) => f.severity === severity);
    if (group.length === 0) continue;
    lines.push(`## ${SEVERITY_LABEL[severity]}`, "");
    for (const f of group) {
      lines.push(`### ${f.title}`);
      lines.push(`- id: \`${f.id}\` (${f.check})`);
      if (f.location) lines.push(`- location: \`${f.location}\``);
      if (f.evidence) lines.push(`- evidence: \`${f.evidence}\``);
      lines.push(`- detail: ${f.detail}`);
      lines.push(`- fix: ${f.fix}`);
      lines.push("");
    }
  }

  const skipped = results.filter((r) => !r.ran);
  if (skipped.length > 0) {
    lines.push("## Skipped checks", "");
    for (const r of skipped) {
      lines.push(`- **${r.check}**: ${r.skippedReason ?? "unknown reason"}`);
    }
    lines.push("");
  }

  return lines.join("\n");
}

export function renderJson(results: CheckResult[]): string {
  return JSON.stringify(results, null, 2);
}

/** A copy-paste block a coding agent can act on directly: one bullet per finding, grouped by severity. */
export function renderAgentTasks(results: CheckResult[]): string {
  const findings = allFindings(results);
  const lines: string[] = [];
  lines.push("## keysnag agent tasks", "");
  lines.push(summaryLine(results), "");

  if (findings.length === 0) {
    lines.push("No findings to act on.");
    return lines.join("\n");
  }

  for (const severity of SEVERITY_ORDER) {
    const group = findings.filter((f) => f.severity === severity);
    if (group.length === 0) continue;
    for (const f of group) {
      const location = f.location ? ` at \`${f.location}\`` : "";
      lines.push(
        `- [${SEVERITY_LABEL[severity].toUpperCase()}] ${f.title}${location}: ${f.fix}`,
      );
    }
  }

  return lines.join("\n");
}
