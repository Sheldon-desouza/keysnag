// Cross-account isolation test against the Supabase PostgREST API.
// Only ever talks to ctx.supabaseUrl, using the two user-supplied JWTs (C3: user-supplied targets only).
import { Client } from "pg";
import type { Check, CheckContext, CheckResult, Finding } from "../types.js";

const MAX_TABLES = 40;
const REQUEST_TIMEOUT_MS = 10_000;
const USER_AGENT = "vibeguard-scan";

/** Columns that plausibly identify the row's owner. */
const OWNER_COLUMN = /^(user_id|owner|owner_id|profile_id|created_by|account_id)$/i;
/** Columns we will never guess-write to for the no-op PATCH test. */
const UNSAFE_COLUMN = /^(id|uuid|.*_id|created_at|updated_at|inserted_at)$/i;

interface FetchJsonResult {
  status: number;
  body: unknown;
}

function decodeJwtSub(token: string): string | undefined {
  try {
    const parts = token.split(".");
    if (parts.length < 2) return undefined;
    const payloadB64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = payloadB64.padEnd(payloadB64.length + ((4 - (payloadB64.length % 4)) % 4), "=");
    const json = Buffer.from(padded, "base64").toString("utf8");
    const payload = JSON.parse(json) as { sub?: string };
    return payload.sub;
  } catch {
    return undefined;
  }
}

async function fetchJson(
  url: string,
  headers: Record<string, string>,
  init?: { method?: string; body?: string }
): Promise<FetchJsonResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method: init?.method ?? "GET",
      headers: { "User-Agent": USER_AGENT, ...headers },
      body: init?.body,
      signal: controller.signal,
    });
    let body: unknown = undefined;
    try {
      body = await res.json();
    } catch {
      body = undefined;
    }
    return { status: res.status, body };
  } finally {
    clearTimeout(timer);
  }
}

async function listTablesFromPg(pgUrl: string): Promise<string[]> {
  const client = new Client({ connectionString: pgUrl });
  try {
    await client.connect();
    const res = await client.query<{ table_name: string }>(
      `select table_name
       from information_schema.tables
       where table_schema = 'public' and table_type = 'BASE TABLE'
       order by table_name`
    );
    return res.rows.map((r) => r.table_name);
  } finally {
    await client.end().catch(() => {});
  }
}

async function listTablesFromOpenApi(supabaseUrl: string, anonKey: string): Promise<string[]> {
  const { body } = await fetchJson(`${supabaseUrl.replace(/\/$/, "")}/rest/v1/`, {
    apikey: anonKey,
    Authorization: `Bearer ${anonKey}`,
    Accept: "application/openapi+json",
  });
  if (!body || typeof body !== "object") return [];
  const doc = body as { definitions?: Record<string, unknown>; paths?: Record<string, unknown> };
  const names = new Set<string>();
  if (doc.definitions) for (const k of Object.keys(doc.definitions)) names.add(k);
  if (doc.paths) {
    for (const p of Object.keys(doc.paths)) {
      const name = p.replace(/^\//, "");
      if (name) names.add(name);
    }
  }
  return [...names];
}

const check: Check = {
  name: "twoaccount",
  description:
    "Tests, using two real signed-in accounts, whether one Supabase user can read or modify another user's rows through the REST API.",
  requires: ["supabaseUrl", "tokenA", "tokenB"],
  async run(ctx: CheckContext): Promise<CheckResult> {
    if (!ctx.supabaseAnonKey) {
      return {
        check: check.name,
        ran: false,
        skippedReason: "supabaseAnonKey is missing (needed for the apikey header on every REST request)",
        findings: [],
      };
    }

    const findings: Finding[] = [];
    const base = ctx.supabaseUrl!.replace(/\/$/, "");
    const anonKey = ctx.supabaseAnonKey;
    const tokenA = ctx.tokenA!;
    const tokenB = ctx.tokenB!;
    const subA = decodeJwtSub(tokenA);
    const subB = decodeJwtSub(tokenB);

    let tables: string[] = [];
    try {
      if (ctx.pgUrl) {
        tables = await listTablesFromPg(ctx.pgUrl);
      } else {
        tables = await listTablesFromOpenApi(base, anonKey);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        check: check.name,
        ran: true,
        findings: [
          {
            id: "twoaccount.table_list_failed",
            check: check.name,
            severity: "info",
            title: "could not list tables for the cross-account test",
            detail: `vibeguard could not enumerate tables to test. Error: ${message}`,
            fix: "Provide a working pgUrl, or ensure the PostgREST OpenAPI root is reachable with the anon key.",
          },
        ],
      };
    }

    if (tables.length === 0) {
      return {
        check: check.name,
        ran: true,
        findings: [
          {
            id: "twoaccount.no_tables",
            check: check.name,
            severity: "info",
            title: "no tables found to test for cross-account access",
            detail: "vibeguard could not discover any public tables via pgUrl or the PostgREST OpenAPI document, so the cross-account test could not run against anything.",
            fix: "Provide VG_PG_URL, or check that the Supabase REST API is reachable.",
          },
        ],
      };
    }

    const bounded = tables.slice(0, MAX_TABLES);
    const headersFor = (token: string) => ({
      apikey: anonKey,
      Authorization: `Bearer ${token}`,
    });

    for (const table of bounded) {
      let rowsA: unknown;
      let rowsB: unknown;
      try {
        const resA = await fetchJson(`${base}/rest/v1/${table}?select=*&limit=5`, headersFor(tokenA));
        rowsA = resA.body;
        const resB = await fetchJson(`${base}/rest/v1/${table}?select=*&limit=5`, headersFor(tokenB));
        rowsB = resB.body;
      } catch (err) {
        ctx.log(`twoaccount: request failed for table ${table}: ${err instanceof Error ? err.message : String(err)}`);
        continue;
      }

      if (!Array.isArray(rowsB) || rowsB.length === 0) continue;

      // Look for an ownership-style column on B's rows that names someone other than B.
      let foreignRow: Record<string, unknown> | undefined;
      let ownerColumn: string | undefined;
      for (const row of rowsB) {
        if (typeof row !== "object" || row === null) continue;
        const record = row as Record<string, unknown>;
        for (const key of Object.keys(record)) {
          if (!OWNER_COLUMN.test(key)) continue;
          const value = record[key];
          if (typeof value === "string" && value.length > 0 && value !== subB) {
            foreignRow = record;
            ownerColumn = key;
            break;
          }
        }
        if (foreignRow) break;
      }

      if (foreignRow && ownerColumn) {
        findings.push({
          id: "twoaccount.cross_read",
          check: check.name,
          severity: "critical",
          title: `user B can read user A's rows in ${table}`,
          detail: `Using account B's own session token, vibeguard read rows from public.${table} whose "${ownerColumn}" column belongs to a different user (not B). This means the REST API returns other users' data to anyone with a valid login, regardless of who owns the row.`,
          location: `public.${table}`,
          evidence: `column "${ownerColumn}" on a row returned to B did not match B's own id (value redacted)`,
          fix: `Add or fix a Row Level Security policy on public.${table} so SELECT is scoped to USING (auth.uid() = ${ownerColumn}).`,
        });

        // Non-destructive write test: only attempt if we have an obvious id and an obvious
        // non-key, non-timestamp column to no-op update. Otherwise skip and note why.
        const idValue = foreignRow["id"];
        const writableKey = Object.keys(foreignRow).find(
          (k) => !UNSAFE_COLUMN.test(k) && k !== ownerColumn && typeof foreignRow[k] === "string"
        );
        if (idValue === undefined || writableKey === undefined) {
          ctx.log(
            `twoaccount: skipped write test on ${table} (no obvious primary key or safe non-key column to no-op update without guessing)`
          );
        } else {
          try {
            const noopValue = foreignRow[writableKey];
            const patchRes = await fetchJson(
              `${base}/rest/v1/${table}?id=eq.${encodeURIComponent(String(idValue))}`,
              {
                ...headersFor(tokenB),
                "Content-Type": "application/json",
                Prefer: "return=representation",
              },
              { method: "PATCH", body: JSON.stringify({ [writableKey]: noopValue }) }
            );
            if (
              patchRes.status >= 200 &&
              patchRes.status < 300 &&
              Array.isArray(patchRes.body) &&
              patchRes.body.length > 0
            ) {
              findings.push({
                id: "twoaccount.cross_write",
                check: check.name,
                severity: "critical",
                title: `user B can modify user A's rows in ${table}`,
                detail: `Using account B's own session token, vibeguard performed a no-op update (same value written back) on a row in public.${table} owned by another user, and the API accepted it. A real attacker could change any writable column on other users' rows here.`,
                location: `public.${table}`,
                evidence: `PATCH by B on a row owned by another user returned ${patchRes.status} with the row affected`,
                fix: `Add or fix a Row Level Security policy on public.${table} so UPDATE is scoped to USING (auth.uid() = ${ownerColumn}) WITH CHECK (auth.uid() = ${ownerColumn}).`,
              });
            }
          } catch (err) {
            ctx.log(`twoaccount: write test failed for table ${table}: ${err instanceof Error ? err.message : String(err)}`);
          }
        }
      }
      void rowsA; // read for parity/future comparison; not otherwise needed once B's own data proves the leak
    }

    return { check: check.name, ran: true, findings };
  },
};

export default check;
