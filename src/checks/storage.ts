// storage: Supabase Storage misconfiguration + edge function / cron secret checks.
// Two halves: a live pg half (only when ctx.pgUrl is set) and a repo-static half
// that always runs (requires: []). Never blocks on missing pgUrl; logs and skips
// that half only, per C1.
import { readFile, readdir } from "node:fs/promises";
import { join, relative, extname } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { Client } from "pg";
import type { Check, CheckContext, CheckResult, Finding } from "../types.js";

const pexec = promisify(execFile);

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", ".next", "build", ".claude"]);
const SKIP_EXTS = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".woff", ".woff2",
  ".ttf", ".eot", ".pdf", ".zip", ".gz", ".tgz", ".mp4", ".mov", ".mp3",
  ".wasm", ".node", ".lock", ".map",
]);
const MAX_FILE_BYTES = 2 * 1024 * 1024;

const SENSITIVE_BUCKET_NAME = /avatar|upload|user|private|document|attachment|invoice|kyc|id/i;

interface BucketRow {
  id: string;
  name: string;
  public: boolean;
}

interface PolicyRow {
  policyname: string;
  qual: string | null;
  with_check: string | null;
}

function isWideOpen(expr: string | null): boolean {
  if (!expr) return false;
  const e = expr.trim().toLowerCase();
  return e === "true" || e === "(true)";
}

async function walkRepo(root: string): Promise<string[]> {
  const results: string[] = [];
  async function walk(dir: string) {
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        await walk(join(dir, entry.name));
      } else if (entry.isFile()) {
        if (SKIP_EXTS.has(extname(entry.name))) continue;
        results.push(join(dir, entry.name));
      }
    }
  }
  await walk(root);
  return results;
}

/** Git-tracked (or untracked-not-ignored) files, honouring ctx.changedFiles. */
async function getScanFiles(repoDir: string, changedFiles: string[] | undefined): Promise<string[]> {
  if (changedFiles && changedFiles.length > 0) {
    return changedFiles.map((f) => join(repoDir, f));
  }
  try {
    const { stdout } = await pexec(
      "git",
      ["-C", repoDir, "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
      { maxBuffer: 128 * 1024 * 1024 },
    );
    const rel = stdout.split("\u0000").filter(Boolean);
    if (rel.length === 0) return await walkRepo(repoDir);
    return rel.filter((r) => !SKIP_EXTS.has(extname(r))).map((r) => join(repoDir, r));
  } catch {
    return await walkRepo(repoDir);
  }
}

function isCronOrInternalRoute(relPath: string): boolean {
  const norm = relPath.replace(/\\/g, "/").toLowerCase();
  if (!/\.(ts|tsx|js|jsx)$/.test(norm)) return false;
  return norm.includes("/api/cron") || norm.includes("/api/internal") || norm.includes("cron");
}

const CRON_SECRET_SIGNAL = /authorization|x-cron-secret|cron_secret|bearer/i;

async function runPgHalf(pgUrl: string, log: (msg: string) => void): Promise<Finding[]> {
  const findings: Finding[] = [];
  const client = new Client({ connectionString: pgUrl });
  try {
    await client.connect();
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    log(`storage: could not connect for the pg audit: ${message}`);
    return [
      {
        id: "storage.connect_failed",
        check: "storage",
        severity: "info",
        title: "could not connect for the storage audit",
        detail: `keysnag could not connect to the database with the supplied pgUrl, so the storage buckets/policies audit did not run. Error: ${message}`,
        fix: "Check that the pg connection string is correct, the read-only role exists, and the database allows connections from this machine.",
      },
    ];
  }

  try {
    const buckets = await client.query<BucketRow>(`select id, name, public from storage.buckets`);
    for (const b of buckets.rows) {
      if (!b.public) continue;
      const critical = SENSITIVE_BUCKET_NAME.test(b.name);
      findings.push({
        id: "storage.public_bucket",
        check: "storage",
        severity: critical ? "critical" : "high",
        title: `Storage bucket "${b.name}" is public`,
        detail: critical
          ? `The bucket "${b.name}" is public and its name suggests it holds user-uploaded or sensitive files (avatars, documents, invoices, IDs). Anyone with a file's URL, or who can guess/enumerate it, can read it with no authentication.`
          : `The bucket "${b.name}" is public. Any file in it is readable by anyone with the URL, with no authentication.`,
        location: `storage.buckets.${b.name}`,
        fix: `If this bucket should not be world-readable, set it to private in the Supabase dashboard (or update storage.buckets set public = false where name = '${b.name}') and serve files through signed URLs instead.`,
      });
    }

    const policies = await client.query<PolicyRow>(
      `select policyname, qual, with_check
       from pg_policies
       where schemaname = 'storage' and tablename = 'objects'`,
    );
    for (const p of policies.rows) {
      if (isWideOpen(p.qual) || isWideOpen(p.with_check)) {
        findings.push({
          id: "storage.policy_wide_open",
          check: "storage",
          severity: "high",
          title: `Storage policy "${p.policyname}" allows all objects (USING true)`,
          detail: `The policy "${p.policyname}" on storage.objects has no real condition, so it matches every object for every caller, regardless of which bucket or owner it belongs to.`,
          location: `storage.objects.${p.policyname}`,
          fix: `Rewrite the policy to check bucket_id and ownership, e.g. USING (bucket_id = 'avatars' AND auth.uid() = owner), instead of USING (true).`,
        });
      }
    }
  } finally {
    await client.end().catch(() => {});
  }

  return findings;
}

async function runStaticHalf(repoDir: string, changedFiles: string[] | undefined, log: (msg: string) => void): Promise<Finding[]> {
  const findings: Finding[] = [];
  const files = await getScanFiles(repoDir, changedFiles);

  for (const filePath of files) {
    const relPath = relative(repoDir, filePath).replace(/\\/g, "/");
    let text: string;
    try {
      const { stat } = await import("node:fs/promises");
      const info = await stat(filePath);
      if (info.size > MAX_FILE_BYTES) continue;
      text = await readFile(filePath, "utf8");
    } catch {
      continue;
    }
    if (text.includes("\u0000")) continue;

    const base = relPath.split("/").pop() ?? "";

    // supabase/config.toml: [functions.<name>] section with verify_jwt = false
    if (base === "config.toml" && relPath.includes("supabase")) {
      const lines = text.split("\n");
      let currentFn: string | null = null;
      for (let i = 0; i < lines.length; i++) {
        const sectionMatch = lines[i].match(/^\s*\[functions\.([^\]]+)\]/);
        if (sectionMatch) {
          currentFn = sectionMatch[1];
          continue;
        }
        if (/^\s*\[/.test(lines[i]) && !sectionMatch) currentFn = null;
        if (currentFn && /verify_jwt\s*=\s*false/i.test(lines[i])) {
          findings.push({
            id: "storage.edge_fn_no_jwt",
            check: "storage",
            severity: "high",
            title: `Edge function "${currentFn}" is deployed with verify_jwt = false`,
            detail: `The function "${currentFn}" has JWT verification disabled in supabase/config.toml, so it accepts requests with no Supabase auth token at all. Anyone can invoke it directly.`,
            location: `${relPath}:${i + 1}`,
            fix: `Remove verify_jwt = false (or set it to true) unless this function is intentionally public, and if it must be public, add its own explicit authorization check inside the function.`,
          });
        }
      }
    }

    // deploy scripts using --no-verify-jwt
    if (/--no-verify-jwt/.test(text)) {
      const lineIdx = text.split("\n").findIndex((l) => l.includes("--no-verify-jwt"));
      findings.push({
        id: "storage.edge_fn_no_jwt",
        check: "storage",
        severity: "high",
        title: "Edge function deploy script disables JWT verification",
        detail: "This deploy command passes --no-verify-jwt, so the deployed function accepts requests with no Supabase auth token at all.",
        location: `${relPath}:${lineIdx + 1}`,
        fix: "Remove --no-verify-jwt from the deploy command unless this function is intentionally public, and if it must be public, add its own explicit authorization check inside the function.",
      });
    }

    // cron / internal routes with no shared-secret check
    if (isCronOrInternalRoute(relPath)) {
      if (!CRON_SECRET_SIGNAL.test(text)) {
        findings.push({
          id: "storage.cron_no_secret",
          check: "storage",
          severity: "high",
          title: `Cron/internal route "${relPath}" never checks a shared secret`,
          detail: "This route lives under a cron/internal path but never reads an authorization header, x-cron-secret header, CRON_SECRET, or a Bearer token, so anyone who finds the URL can trigger it.",
          location: `${relPath}:1`,
          fix: "Require a shared secret on every request, e.g. compare the Authorization/x-cron-secret header against process.env.CRON_SECRET before doing any work, and return 401 otherwise.",
        });
      }
    }
  }

  return findings;
}

const check: Check = {
  name: "storage",
  description: "Audits Supabase storage buckets/policies (when a pgUrl is given) and, statically, edge functions deployed without JWT verification and cron/internal routes with no shared secret.",
  requires: [],
  async run(ctx: CheckContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const repoDir = ctx.repoDir ?? ".";

    if (ctx.pgUrl) {
      findings.push(...(await runPgHalf(ctx.pgUrl, ctx.log)));
    } else {
      ctx.log("storage: no pgUrl supplied, skipping the storage buckets/policies audit (static checks still run)");
    }

    findings.push(...(await runStaticHalf(repoDir, ctx.changedFiles, ctx.log)));

    return { check: check.name, ran: true, findings };
  },
};

export default check;
