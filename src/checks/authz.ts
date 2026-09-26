// authz: static scan of Next.js App Router route handlers, Pages API routes, and
// server actions ("use server") for broken access control (T2). Three rules:
//   authz.route_without_auth        - queries the DB with no auth check in the same file
//   authz.client_supplied_identity  - filters a query by an identity id taken from the request
//   authz.admin_route_no_role_check - an /admin route with no role/admin check
// Deterministic regex/heuristics only. Per the threat model's precision principle,
// these ship as `high` (warn) until dogfooded; only the write-path escalation for
// route_without_auth is `critical`.
import { readFile, readdir, stat } from "node:fs/promises";
import { join, relative, extname } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { Check, CheckContext, CheckResult, Finding } from "../types.js";

const pexec = promisify(execFile);

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", ".next", "build", ".claude", ".vercel", "coverage", ".turbo", "out"]);

const SKIP_EXTS = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".woff", ".woff2",
  ".ttf", ".eot", ".pdf", ".zip", ".gz", ".tgz", ".mp4", ".mov", ".mp3",
  ".wasm", ".node", ".lock", ".map",
]);

const MAX_FILE_BYTES = 2 * 1024 * 1024;

// Path substrings that mark a route as clearly public: no identity to protect, or
// another check's job (cron -> storage.cron_no_secret).
const PUBLIC_PATH_HINTS = [
  "webhook", "health", "ping", "og", "sitemap", "robots", "callback", "cron", "public", "share",
];

// Evidence a file performs a data access.
const DATA_ACCESS_RE = /supabase\.from\(|prisma\.|db\.|sql`|\.rpc\(|drizzle/;

// Evidence a file already checks the caller's identity.
const AUTH_INDICATORS = [
  "getUser(", "getSession(", "auth()", "getServerSession(", "currentUser(",
  "requireAuth", "withAuth", "verifyJwt", "verifyToken",
  "requireAdmin", "requireUser", "requireSession", "requireRole",
  "getAuthUser", "assertAuth", "isAuthenticated", "withApiAuth",
  "protectRoute", "checkAuth",
];
const AUTHZ_HEADER_RE = /authorization/i;

// Evidence a file writes.
const WRITE_RE = /\.(insert|update|delete|upsert|rpc)\(/;

const IDENTITY_KEYS = ["userId", "user_id", "ownerId", "owner_id", "accountId"];

const QUERY_FILTER_RE = /\.eq\(|where\s*\(|WHERE\s/i;

// (C4/precision calibration, ledger item 13c) the bare word "admin" (an import path
// like @/lib/admin-utils, or the route path itself) is not a role check: require an
// actual check call or comparison. The named helpers (requireAdmin(, checkAdmin(, ...)
// are covered, plus any other identifier that carries "admin"/"role" AND is invoked as
// a function (e.g. checkAdminEmail(user.email), a real check seen in a production app) so
// this doesn't regress into re-matching a bare, uncalled mention.
// Verify cycle 2: `\w*admin\w*\(` also matched `createAdminClient()` (a service
// client, not a gate), silencing the rule on a route that only checked login. An
// admin-named call counts only when it starts with a CHECK verb.
const ADMIN_ROLE_CHECK_RE =
  /requireAdmin\(|assertAdmin\(|checkAdmin\(|isAdmin\(|is_admin\(|requireRole\(|\b(?:check|require|assert|ensure|verify|is|has|guard|validate)\w*admin\w*\s*\(|\.role\s*(?:===|!==|==|!=)|role\s*(?:===|==)\s*["']/i;

const EXPORT_ROUTE_FN_RE = /^\s*export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE)\b/;

/** Location for admin_route_no_role_check: the line of the first exported route
 * handler function, per ledger item 13c, so the finding points at the handler
 * instead of always :1. */
function firstExportedRouteFnLine(text: string): number {
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    if (EXPORT_ROUTE_FN_RE.test(lines[i])) return i + 1;
  }
  return 1;
}

/**
 * Strip // and /* *\/ comments so signal-matching (auth/role/data-access/identity)
 * never fires on, or is never suppressed by, a mention inside a comment. Newlines
 * are preserved so every downstream :line location stays accurate against the
 * original text.
 */
function stripComments(text: string): string {
  const noBlock = text.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " "));
  return noBlock.replace(/\/\/.*$/gm, (m) => " ".repeat(m.length));
}

/** Best-effort: read middleware.ts/js at the repo root and extract matcher path prefixes. */
async function loadMiddlewareMatchers(repoDir: string): Promise<string[]> {
  const candidates = ["middleware.ts", "middleware.js", "src/middleware.ts", "src/middleware.js"];
  for (const rel of candidates) {
    try {
      const text = await readFile(join(repoDir, rel), "utf8");
      const matcherMatch = text.match(/matcher\s*:\s*(\[[\s\S]*?\]|["'`][^"'`]+["'`])/);
      if (!matcherMatch) continue;
      const strings = [...matcherMatch[1].matchAll(/["'`]([^"'`]+)["'`]/g)].map((m) => m[1]);
      return strings.map((s) => s.split(/[:*]/)[0].replace(/\/$/, ""));
    } catch {
      // no middleware at this candidate path, try the next
    }
  }
  return [];
}

function routeCoveredByMiddleware(routePath: string, matchers: string[]): boolean {
  return matchers.some((prefix) => prefix.length > 0 && routePath.startsWith(prefix));
}

/** Convert a route-handler file path to the URL path it serves (best-effort). */
function filePathToRoutePath(relPath: string): string {
  const norm = relPath.replace(/\\/g, "/");

  const appMatch = norm.match(/(?:^|\/)app\/(.*)\/route\.(ts|tsx|js|jsx)$/);
  if (appMatch) {
    const segments = (appMatch[1] ?? "")
      .split("/")
      .filter((seg) => seg.length > 0 && !/^\(.*\)$/.test(seg)); // drop route groups
    return "/" + segments.join("/");
  }
  const appRootMatch = norm.match(/(?:^|\/)app\/route\.(ts|tsx|js|jsx)$/);
  if (appRootMatch) return "/";

  const pagesMatch = norm.match(/(?:^|\/)pages\/(api\/.*)\.(ts|tsx|js|jsx)$/);
  if (pagesMatch) {
    let seg = pagesMatch[1];
    if (seg.endsWith("/index")) seg = seg.slice(0, -"/index".length);
    return "/" + seg;
  }

  return "/" + norm;
}

function isInScope(relPath: string, text: string): boolean {
  const norm = relPath.replace(/\\/g, "/");
  const isAppRoute = /(?:^|\/)app\/.*route\.(ts|tsx|js|jsx)$/.test(norm);
  const isPagesApi = /(?:^|\/)pages\/api\/.*\.(ts|tsx|js|jsx)$/.test(norm);
  const firstLines = text.split("\n").slice(0, 5).join("\n");
  const hasUseServer = /["']use server["'];?/.test(firstLines);
  return isAppRoute || isPagesApi || hasUseServer;
}

function isClearlyPublic(routePath: string): boolean {
  const lower = routePath.toLowerCase();
  if (/^\/api\/auth\//.test(lower)) return true; // auth flows (login/signup/confirm/etc.) are public by nature
  return PUBLIC_PATH_HINTS.some((hint) => lower.includes(hint));
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

/** Same git-aware file listing pattern as secrets.ts: tracked + untracked-not-ignored, else a walk. */
async function getScanFiles(repoDir: string, log: (msg: string) => void): Promise<string[]> {
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
    log("authz: not a git repo, walking the filesystem");
    return await walkRepo(repoDir);
  }
}

function checkRouteWithoutAuth(
  relPath: string,
  routePath: string,
  text: string,
  matchers: string[],
): Finding | null {
  if (!DATA_ACCESS_RE.test(text)) return null;
  const hasAuthIndicator = AUTH_INDICATORS.some((tok) => text.includes(tok)) || AUTHZ_HEADER_RE.test(text);
  if (hasAuthIndicator) return null;
  if (routeCoveredByMiddleware(routePath, matchers)) return null;

  const critical = WRITE_RE.test(text);
  return {
    id: "authz.route_without_auth",
    check: "authz",
    severity: critical ? "critical" : "high",
    title: critical
      ? "Route writes to the database with no auth check in the file"
      : "Route queries the database with no auth check in the file",
    detail:
      `This handler at ${routePath} performs a data access (supabase/prisma/db/sql/rpc) but the file ` +
      "has no call to getUser/getSession/auth()/getServerSession/currentUser, no requireAuth/withAuth/" +
      "verify helper, no authorization header check, and no middleware matcher covering this path.",
    location: `${relPath}:1`,
    fix: "Verify the caller's identity before touching the database: call supabase.auth.getUser() (or your session helper) and return 401 if there is no user, or add this path to a middleware matcher that enforces auth.",
  };
}

// A strict admin/role gate is a pattern that does NOT count as a generic auth signal here.
const OPERATOR_GATE_RE = /requireAdmin|assertAdmin|checkAdmin|isAdmin\s*\(|is_admin\s*\(/;

// (ledger item 13d) requireRole('editor') is not an operator gate: only requireRole(...)
// whose argument names an operator-shaped role counts.
const REQUIRE_ROLE_CALL_RE = /requireRole\s*\(\s*["'`]([^"'`]+)["'`]/g;
const OPERATOR_ROLE_NAME_RE = /admin|owner|operator|superuser|staff/i;

function hasOperatorGate(text: string): boolean {
  if (OPERATOR_GATE_RE.test(text)) return true;
  for (const m of text.matchAll(REQUIRE_ROLE_CALL_RE)) {
    if (OPERATOR_ROLE_NAME_RE.test(m[1])) return true;
  }
  return false;
}

function checkClientSuppliedIdentity(relPath: string, text: string): Finding | null {
  if (!QUERY_FILTER_RE.test(text)) return null;
  // An operator route (requireAdmin etc.) acting on another user's row by an explicit id is the
  // legitimate use of a client-supplied identity: the risk this rule targets is an ordinary user
  // impersonating another, and an admin gate removes that caller. Calibrated on a real repo.
  if (hasOperatorGate(text)) return null;
  for (const key of IDENTITY_KEYS) {
    const readRe = new RegExp(
      `body\\.${key}\\b|body\\[["']${key}["']\\]|searchParams\\.get\\(["']${key}["']\\)|` +
        `params\\.${key}\\b|params\\[["']${key}["']\\]|req\\.query\\.${key}\\b|query\\.${key}\\b`,
      "i",
    );
    const match = readRe.exec(text);
    if (match) {
      const line = text.slice(0, match.index).split("\n").length;
      return {
        id: "authz.client_supplied_identity",
        check: "authz",
        severity: "high",
        title: `Query filtered by a client-supplied "${key}" instead of the authenticated user`,
        detail:
          `The identity key "${key}" is read from the request (body/searchParams/params) and then used ` +
          "in a query filter (.eq/where). Any caller can pass someone else's id and read or edit that " +
          "person's rows (IDOR).",
        location: `${relPath}:${line}`,
        fix: `Ignore the client-supplied "${key}" and derive the identity from the verified session (e.g. supabase.auth.getUser()) before filtering the query.`,
      };
    }
  }
  return null;
}

function checkAdminRouteNoRoleCheck(relPath: string, routePath: string, text: string): Finding | null {
  if (!routePath.toLowerCase().includes("/admin")) return null;
  if (ADMIN_ROLE_CHECK_RE.test(text)) return null;
  return {
    id: "authz.admin_route_no_role_check",
    check: "authz",
    severity: "high",
    title: "Admin route has no role/admin check",
    detail:
      `${routePath} is an admin route but the handler never checks role/isAdmin/is_admin. Any ` +
      "authenticated (or unauthenticated) caller who reaches this path can use admin functionality.",
    location: `${relPath}:${firstExportedRouteFnLine(text)}`,
    fix: "Look up the caller's role (e.g. a role/is_admin column or claim) after verifying their session, and return 403 unless it grants admin access.",
  };
}

async function scanRepo(repoDir: string, changedFiles: string[] | undefined, log: (msg: string) => void): Promise<Finding[]> {
  const findings: Finding[] = [];
  const matchers = await loadMiddlewareMatchers(repoDir);

  let files = await getScanFiles(repoDir, log);
  if (changedFiles && changedFiles.length > 0) {
    const changedSet = new Set(changedFiles.map((f) => f.replace(/\\/g, "/")));
    files = files.filter((f) => changedSet.has(relative(repoDir, f).replace(/\\/g, "/")));
  }

  for (const filePath of files) {
    let info;
    try {
      info = await stat(filePath);
    } catch {
      continue;
    }
    if (info.size > MAX_FILE_BYTES) continue;

    let text: string;
    try {
      text = await readFile(filePath, "utf8");
    } catch {
      continue;
    }
    if (text.includes("\u0000")) continue;

    const relPath = relative(repoDir, filePath).replace(/\\/g, "/");
    if (!isInScope(relPath, text)) continue;

    const routePath = filePathToRoutePath(relPath);
    if (isClearlyPublic(routePath)) continue;

    // Match auth/role/data-access/identity signals against comment-stripped text
    // (line numbers are preserved) so a mention inside a comment can never
    // suppress a real finding, and a real check is never mistaken for one.
    const stripped = stripComments(text);

    const a = checkRouteWithoutAuth(relPath, routePath, stripped, matchers);
    if (a) findings.push(a);

    const b = checkClientSuppliedIdentity(relPath, stripped);
    if (b) findings.push(b);

    const c = checkAdminRouteNoRoleCheck(relPath, routePath, stripped);
    if (c) findings.push(c);
  }

  return findings;
}

const authzCheck: Check = {
  name: "authz",
  description: "Scans Next.js route handlers, Pages API routes and server actions for missing auth checks, client-trusted identity, and unguarded admin routes.",
  requires: [],
  async run(ctx: CheckContext): Promise<CheckResult> {
    const repoDir = ctx.repoDir ?? ".";
    try {
      const findings = await scanRepo(repoDir, ctx.changedFiles, ctx.log);
      ctx.log(`authz: scanned ${repoDir}, found ${findings.length} finding(s)`);
      return { check: "authz", ran: true, findings };
    } catch (err) {
      ctx.log(`authz: scan failed: ${(err as Error).message}`);
      return { check: "authz", ran: true, findings: [] };
    }
  },
};

export default authzCheck;
