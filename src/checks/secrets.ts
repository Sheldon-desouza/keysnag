// secrets: scans the local repo (and optionally a deployed site's JS bundles) for
// leaked credentials. Never puts a live secret value in a finding; always maskSecret().
import { readFile, readdir, stat } from "node:fs/promises";
import { join, relative, extname } from "node:path";
import type { Check, CheckContext, CheckResult, Finding, Severity } from "../types.js";
import { maskSecret } from "../types.js";

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", ".next", "build"]);

// extensions we don't bother reading as text (binary/media/lockfiles/etc.)
const SKIP_EXTS = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".woff", ".woff2",
  ".ttf", ".eot", ".pdf", ".zip", ".gz", ".tgz", ".mp4", ".mov", ".mp3",
  ".wasm", ".node", ".lock", ".map",
]);

const MAX_FILE_BYTES = 2 * 1024 * 1024; // 2MB, skip anything bigger
const MAX_BUNDLE_FILES = 30;
const MAX_BUNDLE_BYTES = 3 * 1024 * 1024;

interface PatternDef {
  id: string;
  title: string;
  regex: RegExp;
  severity: Severity;
  fix: string;
}

// generic patterns that don't need JWT decoding
const PATTERNS: PatternDef[] = [
  {
    id: "secret.stripe_key",
    title: "Stripe secret key found",
    regex: /\b(sk_live_[A-Za-z0-9]{16,}|sk_test_[A-Za-z0-9]{16,}|rk_live_[A-Za-z0-9]{16,})\b/g,
    severity: "critical",
    fix: "Revoke this Stripe key in the Stripe dashboard, remove it from the file/bundle, and load it server-side only from an environment variable that is never exposed to the client bundle.",
  },
  {
    id: "secret.openai_key",
    title: "OpenAI API key found",
    regex: /\bsk-[A-Za-z0-9]{20,}\b/g,
    severity: "critical",
    fix: "Revoke this OpenAI key, move it to a server-only environment variable, and never reference it from client components or committed files.",
  },
  {
    id: "secret.anthropic_key",
    title: "Anthropic API key found",
    regex: /\bsk-ant-[A-Za-z0-9-]{20,}\b/g,
    severity: "critical",
    fix: "Revoke this Anthropic key, move it to a server-only environment variable, and never reference it from client components or committed files.",
  },
  {
    id: "secret.google_api_key",
    title: "Google API key found",
    regex: /\bAIza[A-Za-z0-9_-]{30,}\b/g,
    severity: "high",
    fix: "Restrict or regenerate this Google API key in the Google Cloud console, and keep unrestricted keys out of client-shipped code.",
  },
];

// generic KEY/SECRET/TOKEN/PASSWORD = "high-entropy string" assignment
const GENERIC_ASSIGNMENT = /\b([A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD)[A-Z0-9_]*)\s*[:=]\s*["'`]([A-Za-z0-9+/_=.\-]{20,})["'`]/g;

function shannonEntropy(s: string): number {
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / s.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/** Decode a JWT's payload segment without a library. Returns null if not a plausible JWT. */
function decodeJwtPayload(token: string): Record<string, unknown> | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    let b64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4 !== 0) b64 += "=";
    const json = Buffer.from(b64, "base64").toString("utf8");
    return JSON.parse(json);
  } catch {
    return null;
  }
}

const JWT_REGEX = /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g;

/** Files that ship to the browser: public/, client components, or committed .env files. */
function isClientShipped(filePath: string): boolean {
  const norm = filePath.replace(/\\/g, "/");
  if (norm.includes("/public/") || norm.startsWith("public/")) return true;
  if (/\.env(\.|$)/.test(norm.split("/").pop() ?? "")) return true;
  if (/\.(tsx|jsx)$/.test(norm)) return true;
  return false;
}

function isEnvFile(filePath: string): boolean {
  const base = filePath.replace(/\\/g, "/").split("/").pop() ?? "";
  return base === ".env" || base === ".env.local" || /^\.env\./.test(base);
}

function scanTextForSecrets(
  text: string,
  location: (line: number) => string,
  clientShipped: boolean,
  isEnv: boolean,
): Finding[] {
  const findings: Finding[] = [];
  const lines = text.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    // values already reported by a specific rule on this line, so the generic
    // high-entropy rule does not double-report the same credential.
    const matchedValues: string[] = [];

    // JWTs: check for Supabase service_role
    for (const match of line.matchAll(JWT_REGEX)) {
      const token = match[0];
      const payload = decodeJwtPayload(token);
      if (payload && payload["role"] === "service_role") {
        // A service_role JWT bypasses RLS entirely, so it is always critical
        // wherever it is found, not only in client-shipped or .env files.
        matchedValues.push(token);
        findings.push({
          id: "secret.supabase_service_role",
          check: "secrets",
          severity: "critical",
          title: "Supabase service_role key found",
          detail:
            "This is a Supabase service_role JWT, which bypasses Row Level Security entirely. Anyone with this token can read or write any row in your database, no matter which file it sits in." +
            (clientShipped ? " It was found in a file that ships to the browser." : "") +
            (isEnv ? " It was found in a committed .env file." : ""),
          location: location(i + 1),
          evidence: maskSecret(token),
          fix: "Rotate this service_role key in the Supabase dashboard immediately. Never use it outside trusted server code, never commit it, and never bundle it into client-side JavaScript.",
        });
      }
    }

    for (const pat of PATTERNS) {
      pat.regex.lastIndex = 0;
      for (const match of line.matchAll(pat.regex)) {
        const value = match[0];
        matchedValues.push(value);
        const critical = pat.severity === "critical" || clientShipped || isEnv;
        findings.push({
          id: pat.id + (clientShipped ? "_in_client" : ""),
          check: "secrets",
          severity: (clientShipped || isEnv) ? "critical" : pat.severity,
          title: pat.title + (clientShipped ? " (shipped to client)" : isEnv ? " (in committed .env)" : ""),
          detail: critical
            ? "This credential grants live access and was found somewhere it can reach an attacker: a client-shipped file or a committed .env file."
            : "This looks like a live credential committed to the repo.",
          location: location(i + 1),
          evidence: maskSecret(value),
          fix: pat.fix,
        });
      }
    }

    GENERIC_ASSIGNMENT.lastIndex = 0;
    for (const match of line.matchAll(GENERIC_ASSIGNMENT)) {
      const [, ident, value] = match;
      // skip if a specific rule already reported this value on this line (dedup)
      if (matchedValues.some((v) => v === value || v.includes(value) || value.includes(v))) continue;
      // skip clear placeholders
      if (/your[-_]?|example|changeme|placeholder|xxxx|dummy/i.test(value)) continue;
      const entropy = shannonEntropy(value);
      if (entropy < 3.2) continue; // low entropy, likely not a real secret
      findings.push({
        id: "secret.generic_high_entropy",
        check: "secrets",
        severity: clientShipped || isEnv ? "critical" : "medium",
        title: `Possible secret assigned to ${ident}`,
        detail:
          "A high-entropy string is assigned to an identifier that looks like a credential (KEY/SECRET/TOKEN/PASSWORD). This may be a live secret committed to source." +
          (clientShipped ? " It is in a file that ships to the browser." : "") +
          (isEnv ? " It is in a committed .env file." : ""),
        location: location(i + 1),
        evidence: maskSecret(value),
        fix: "Verify whether this is a live credential. If so, rotate it, remove it from source, and load it from a server-only environment variable (never NEXT_PUBLIC_*, never a client component).",
      });
    }
  }

  return findings;
}

async function walkRepo(root: string, log: (msg: string) => void): Promise<string[]> {
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
        const ext = extname(entry.name);
        if (SKIP_EXTS.has(ext)) continue;
        results.push(join(dir, entry.name));
      }
    }
  }

  await walk(root);
  return results;
}

async function scanRepo(repoDir: string, log: (msg: string) => void): Promise<Finding[]> {
  const findings: Finding[] = [];
  const files = await walkRepo(repoDir, log);

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
      continue; // likely binary or unreadable
    }
    // crude binary sniff: presence of NUL bytes
    if (text.includes("\u0000")) continue;

    const relPath = relative(repoDir, filePath);
    const clientShipped = isClientShipped(relPath);
    const isEnv = isEnvFile(relPath);

    findings.push(
      ...scanTextForSecrets(
        text,
        (line) => `${relPath}:${line}`,
        clientShipped,
        isEnv,
      ),
    );
  }

  return findings;
}

async function scanDeployedBundles(
  siteUrl: string,
  log: (msg: string) => void,
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const origin = new URL(siteUrl).origin;

  let html: string;
  try {
    const res = await fetch(siteUrl, {
      signal: AbortSignal.timeout(10_000),
      headers: { "User-Agent": "vibeguard-scan" },
    });
    html = await res.text();
  } catch (err) {
    log(`secrets: could not fetch ${siteUrl}: ${(err as Error).message}`);
    return findings;
  }

  const scriptSrcs = new Set<string>();
  for (const match of html.matchAll(/<script[^>]+src=["']([^"']+)["']/g)) {
    scriptSrcs.add(match[1]);
  }

  const bundleUrls: string[] = [];
  for (const src of scriptSrcs) {
    try {
      const abs = new URL(src, origin).toString();
      if (new URL(abs).origin === origin) bundleUrls.push(abs);
    } catch {
      // ignore malformed src
    }
    if (bundleUrls.length >= MAX_BUNDLE_FILES) break;
  }

  for (const url of bundleUrls) {
    let text: string;
    try {
      const res = await fetch(url, {
        signal: AbortSignal.timeout(10_000),
        headers: { "User-Agent": "vibeguard-scan" },
      });
      if (!res.ok) continue;
      const buf = await res.arrayBuffer();
      if (buf.byteLength > MAX_BUNDLE_BYTES) continue;
      text = Buffer.from(buf).toString("utf8");
    } catch (err) {
      log(`secrets: could not fetch bundle ${url}: ${(err as Error).message}`);
      continue;
    }

    const bundleFindings = scanTextForSecrets(
      text,
      () => url,
      true, // a shipped bundle is client-shipped by definition
      false,
    );
    for (const f of bundleFindings) {
      f.detail = `${f.detail} Found in a JS bundle served to every visitor: ${url}.`;
    }
    findings.push(...bundleFindings);
  }

  return findings;
}

const secretsCheck: Check = {
  name: "secrets",
  description: "Scans the local repo and, if a site URL is given, deployed JS bundles for leaked API keys, service_role JWTs, and other credentials.",
  requires: [],
  async run(ctx: CheckContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const repoDir = ctx.repoDir ?? ".";
    let ranSomething = false;

    try {
      const repoFindings = await scanRepo(repoDir, ctx.log);
      findings.push(...repoFindings);
      ranSomething = true;
      ctx.log(`secrets: scanned repo at ${repoDir}, found ${repoFindings.length} finding(s)`);
    } catch (err) {
      ctx.log(`secrets: repo scan failed: ${(err as Error).message}`);
    }

    if (ctx.siteUrl) {
      try {
        const bundleFindings = await scanDeployedBundles(ctx.siteUrl, ctx.log);
        findings.push(...bundleFindings);
        ranSomething = true;
        ctx.log(`secrets: scanned deployed bundles at ${ctx.siteUrl}, found ${bundleFindings.length} finding(s)`);
      } catch (err) {
        ctx.log(`secrets: bundle scan failed: ${(err as Error).message}`);
      }
    }

    if (!ranSomething) {
      return {
        check: "secrets",
        ran: false,
        skippedReason: "neither repoDir nor siteUrl was available to scan",
        findings: [],
      };
    }

    return { check: "secrets", ran: true, findings };
  },
};

export default secretsCheck;
