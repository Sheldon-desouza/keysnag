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

const ADMIN_ROLE_CHECK_RE = /\brole\b|\badmin\b|isAdmin|is_admin|requireAdmin|requireRole|assertAdmin|checkAdmin/i;

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
const OPERATOR_GATE_RE = /requireAdmin|requireRole|assertAdmin|checkAdmin|isAdmin\s*\(|is_admin\s*\(/;

function checkClientSuppliedIdentity(relPath: string, text: string): Finding | null {
  if (!QUERY_FILTER_RE.test(text)) return null;
  // An operator route (requireAdmin etc.) acting on another user's row by an explicit id is the
  // legitimate use of a client-supplied identity: the risk this rule targets is an ordinary user
  // impersonating another, and an admin gate removes that caller. Calibrated on a real repo.
  if (OPERATOR_GATE_RE.test(text)) return null;
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
    location: `${relPath}:1`,
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
