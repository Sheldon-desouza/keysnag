// Audits Postgres Row Level Security on public tables via a read-only role.
// Connects only to ctx.pgUrl (local-only per C1: this check never reaches the network
// beyond the user's own database connection string).
import { Client } from "pg";
import type { Check, CheckContext, CheckResult, Finding } from "../types.js";

interface TableRow {
  tablename: string;
  rowsecurity: boolean;
}

interface PolicyRow {
  tablename: string;
  policyname: string;
  qual: string | null;
  with_check: string | null;
}

interface GrantRow {
  table_name: string;
  privilege_type: string;
}

function usesOwnershipPredicate(expr: string | null): boolean {
  if (!expr) return false;
  const e = expr.toLowerCase();
  return e.includes("auth.uid()") || /\buser_id\b|\bowner\b|\bowner_id\b/.test(e);
}

function isWideOpen(expr: string | null): boolean {
  if (!expr) return false;
  const e = expr.trim().toLowerCase();
  return e === "true" || e === "(true)";
}

const check: Check = {
  name: "rls",
  description: "Audits Row Level Security on public Postgres tables (missing RLS, permissive policies, anon grants).",
  requires: ["pgUrl"],
  async run(ctx: CheckContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const client = new Client({ connectionString: ctx.pgUrl });

    try {
      await client.connect();
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        check: check.name,
        ran: true,
        findings: [
          {
            id: "rls.connect_failed",
            check: check.name,
            severity: "info",
            title: "could not connect for RLS audit",
            detail: `vibeguard could not connect to the database with the supplied pgUrl, so the RLS audit did not run. Error: ${message}`,
            fix: "Check that VG_PG_URL is correct, the read-only role exists, and the database allows connections from this machine.",
          },
        ],
      };
    }

    try {
      // a) tables with RLS disabled entirely
      const disabled = await client.query<TableRow>(
        `select t.tablename, c.relrowsecurity as rowsecurity
         from pg_tables t
         join pg_class c on c.relname = t.tablename
         join pg_namespace n on n.oid = c.relnamespace and n.nspname = t.schemaname
         where t.schemaname = 'public'`
      );
      for (const row of disabled.rows) {
        if (!row.rowsecurity) {
          findings.push({
            id: "rls.disabled",
            check: check.name,
            severity: "critical",
            title: `RLS disabled on public.${row.tablename}`,
            detail:
              "Row Level Security is off on this table. If it holds user data, any authenticated (or, with a permissive grant, anonymous) API caller can read or write every row in it, not just their own.",
            location: `public.${row.tablename}`,
            fix: `Enable RLS: ALTER TABLE public.${row.tablename} ENABLE ROW LEVEL SECURITY; then add an ownership policy such as USING (auth.uid() = user_id).`,
          });
        }
      }

      // b) RLS enabled but no policies
      const policies = await client.query<PolicyRow>(
        `select tablename, policyname, qual, with_check
         from pg_policies
         where schemaname = 'public'`
      );
      const policyByTable = new Map<string, PolicyRow[]>();
      for (const p of policies.rows) {
        const list = policyByTable.get(p.tablename) ?? [];
        list.push(p);
        policyByTable.set(p.tablename, list);
      }
      for (const row of disabled.rows) {
        if (row.rowsecurity && !policyByTable.has(row.tablename)) {
          findings.push({
            id: "rls.no_policy",
            check: check.name,
            severity: "high",
            title: `RLS on but no policy blocks all or, if forced off, exposes on public.${row.tablename}`,
            detail:
              "Row Level Security is enabled on this table but no policy exists. With RLS enabled and no policy, Postgres denies all rows by default, which usually breaks the app; if RLS is ever force-disabled or bypassed, the table has no protection at all.",
            location: `public.${row.tablename}`,
            fix: `Add an ownership policy, e.g. CREATE POLICY "owner_access" ON public.${row.tablename} USING (auth.uid() = user_id);`,
          });
        }
      }

      // c) policies that are wide open (USING true / WITH CHECK true)
      for (const p of policies.rows) {
        if (isWideOpen(p.qual) || isWideOpen(p.with_check)) {
          findings.push({
            id: "rls.policy_wide_open",
            check: check.name,
            severity: "high",
            title: `policy allows all rows (USING true) on ${p.tablename}`,
            detail: `The policy "${p.policyname}" on public.${p.tablename} has no real condition, so it matches every row for every caller regardless of who owns them.`,
            location: `public.${p.tablename}`,
            fix: `Rewrite the policy to check ownership, e.g. USING (auth.uid() = user_id), instead of USING (true).`,
          });
        }
      }

      // d) policies that only check login, not ownership
      for (const p of policies.rows) {
        if (isWideOpen(p.qual) || isWideOpen(p.with_check)) continue; // already flagged above
        const qual = p.qual ?? "";
        const withCheck = p.with_check ?? "";
        const checksLoginOnly =
          (/auth\.role\(\)|authenticated/i.test(qual) || /auth\.role\(\)|authenticated/i.test(withCheck)) &&
          !usesOwnershipPredicate(qual) &&
          !usesOwnershipPredicate(withCheck);
        if (checksLoginOnly) {
          findings.push({
            id: "rls.login_only_policy",
            check: check.name,
            severity: "medium",
            title: `policy checks only that the user is logged in, not that they own the row on ${p.tablename}`,
            detail: `The policy "${p.policyname}" on public.${p.tablename} allows any authenticated user, without checking that the row belongs to them. Any signed-up user can read or write other users' rows here.`,
            location: `public.${p.tablename}`,
            fix: `Add an ownership check to the policy, e.g. USING (auth.uid() = user_id), rather than relying on auth.role() alone.`,
          });
        }
      }

      // e) anon grants on tables
      const anonGrants = await client.query<GrantRow>(
        `select table_name, privilege_type
         from information_schema.role_table_grants
         where table_schema = 'public'
           and grantee = 'anon'
           and privilege_type in ('SELECT', 'INSERT', 'UPDATE', 'DELETE')`
      );
      const grantsByTable = new Map<string, Set<string>>();
      for (const g of anonGrants.rows) {
        const set = grantsByTable.get(g.table_name) ?? new Set<string>();
        set.add(g.privilege_type);
        grantsByTable.set(g.table_name, set);
      }
      for (const [table, privileges] of grantsByTable) {
        findings.push({
          id: "rls.anon_grant",
          check: check.name,
          severity: "high",
          title: `anon role can ${[...privileges].join("/")} public.${table} directly`,
          detail: `The Postgres "anon" role (used by Supabase for unauthenticated API requests) has ${[...privileges].join(
            ", "
          )} on this table. Combined with weak or missing RLS, this can let anyone on the internet read or write this table without signing in.`,
          location: `public.${table}`,
          fix: `Revoke the grant if unauthenticated access is not intended: REVOKE ${[...privileges].join(
            ", "
          )} ON public.${table} FROM anon; and rely on RLS policies scoped to authenticated users.`,
        });
      }

      // context finding: Supabase signup is open by default
      findings.push({
        id: "rls.open_signup_context",
        check: check.name,
        severity: "info",
        title: "Supabase signup is open by default, and any signed-up user can call the REST API directly",
        detail:
          "By default, Supabase projects allow anyone to create an account, and every table is reachable straight from the browser via the PostgREST API using that account's JWT. This means RLS policies are the only thing standing between a stranger's free account and your users' data, not the app's own UI or server code.",
        fix: "Treat every public table as internet-reachable: make sure RLS is enabled with an ownership policy on each one, and disable public signup if the app should be invite-only.",
      });

      return { check: check.name, ran: true, findings };
    } finally {
      await client.end().catch(() => {});
    }
  },
};

export default check;
