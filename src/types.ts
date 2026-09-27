// keysnag contract. Every check implements Check; the harness consumes CheckResult.
// This file is authoritative. Checks and harness must not redefine these shapes.

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  /** stable slug, e.g. "secret.service_role_in_bundle" */
  id: string;
  /** the check that produced it, e.g. "secrets" */
  check: string;
  severity: Severity;
  /** one line, plain language */
  title: string;
  /** what it is and why it matters, for a non-security founder */
  detail: string;
  /** where: "file:line", a URL, or "schema.table.column" */
  location?: string;
  /** redacted proof. NEVER a live secret value: mask to first 4 + last 4 chars */
  evidence?: string;
  /** concrete remediation, phrased so a coding agent can act on it */
  fix: string;
}

/** All inputs a check may need. A check declares which it requires. */
export interface CheckContext {
  repoDir?: string;
  siteUrl?: string;
  supabaseUrl?: string;
  supabaseAnonKey?: string;
  /** read-only Postgres connection string, for the RLS audit */
  pgUrl?: string;
  /** two signed-in Supabase user JWTs, for the cross-account test */
  tokenA?: string;
  tokenB?: string;
  /** when set, file-based checks scan only these repo-relative paths (pre-push diff mode) */
  changedFiles?: string[];
  /** set false to forbid the one third-party call keysnag can make (OSV.dev CVE lookup) */
  allowOsv?: boolean;
  /** names that must not appear in a public repo (from KEYSNAG_PRIVATE_TERMS; the leaks check also reads a gitignored .keysnag-private) */
  privateTerms?: string[];
  log: (msg: string) => void;
}

export interface CheckResult {
  check: string;
  ran: boolean;
  /** set when ran === false: which context field was missing, in plain words */
  skippedReason?: string;
  findings: Finding[];
}

export interface Check {
  /** slug used in config and the id prefix, e.g. "secrets" */
  name: string;
  /** one line for the report and MCP tool description */
  description: string;
  /** context fields that must be present, else the check is skipped (not failed) */
  requires: (keyof CheckContext)[];
  run(ctx: CheckContext): Promise<CheckResult>;
}

/** Helper for checks: mask a secret so evidence never carries a live value. */
export function maskSecret(v: string): string {
  if (v.length <= 12) return "****";
  return `${v.slice(0, 4)}…${v.slice(-4)} (${v.length} chars)`;
}
