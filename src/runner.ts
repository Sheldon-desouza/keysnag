// Runs a set of checks against a context. Never throws: a missing requirement is a skip,
// a thrown error inside a check becomes an info finding, and the caller always gets results back.
import type { Check, CheckContext, CheckResult, Finding } from "./types.js";

const ENV_VAR_BY_FIELD: Record<string, string> = {
  repoDir: "KEYSNAG_REPO_DIR",
  siteUrl: "KEYSNAG_SITE_URL",
  supabaseUrl: "KEYSNAG_SUPABASE_URL",
  supabaseAnonKey: "KEYSNAG_SUPABASE_ANON_KEY",
  pgUrl: "KEYSNAG_PG_URL",
  tokenA: "KEYSNAG_TOKEN_A",
  tokenB: "KEYSNAG_TOKEN_B",
};

function missingFields(check: Check, ctx: CheckContext): (keyof CheckContext)[] {
  return check.requires.filter((field) => {
    const value = ctx[field];
    return value === undefined || value === "";
  });
}

export async function runChecks(
  ctx: CheckContext,
  enabled: Check[],
): Promise<CheckResult[]> {
  const results: CheckResult[] = [];

  for (const check of enabled) {
    const missing = missingFields(check, ctx);
    if (missing.length > 0) {
      const envVars = missing.map((f) => ENV_VAR_BY_FIELD[f] ?? String(f));
      results.push({
        check: check.name,
        ran: false,
        skippedReason: `missing ${envVars.join(", ")}`,
        findings: [],
      });
      continue;
    }

    try {
      const result = await check.run(ctx);
      results.push(result);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      const finding: Finding = {
        id: `${check.name}.internal_error`,
        check: check.name,
        severity: "info",
        title: `${check.name} check failed to run`,
        detail: `The check threw an unexpected error and was aborted: ${message}`,
        fix: "This is a keysnag bug or an unexpected environment issue, not a finding about your app. Re-run with more context, or report it.",
      };
      results.push({
        check: check.name,
        ran: false,
        skippedReason: `internal error: ${message}`,
        findings: [finding],
      });
    }
  }

  return results;
}
