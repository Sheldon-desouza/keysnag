// backdoor: hunts for deliberately or accidentally hidden covert-access code left by
// an AI coding agent: obfuscated eval chains, hardcoded bypass conditionals, auth-skip
// flags, process.env dumped to a response, unexpected outbound hosts, and stray
// prompt-injection artifacts. Repo-static only, requires: [].
import { readFile, readdir, stat } from "node:fs/promises";
import { join, relative, extname } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { Check, CheckContext, CheckResult, Finding } from "../types.js";

const pexec = promisify(execFile);

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", ".next", "build", ".claude"]);
const SKIP_EXTS = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".woff", ".woff2",
  ".ttf", ".eot", ".pdf", ".zip", ".gz", ".tgz", ".mp4", ".mov", ".mp3",
  ".wasm", ".node", ".lock", ".map",
]);
const MAX_FILE_BYTES = 2 * 1024 * 1024;

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

/** Skip test/fixture/docs/markdown paths, per acceptance criteria. */
function isSkippable(relPath: string): boolean {
  const norm = relPath.replace(/\\/g, "/").toLowerCase();
  if (/\.(md|mdx)$/.test(norm)) return true;
  if (norm.includes("/__tests__/") || norm.includes("/test/") || norm.includes("/tests/")) return true;
  if (/\.(test|spec)\.[jt]sx?$/.test(norm)) return true;
  if (norm.includes("/docs/")) return true;
  return false;
}

const OBFUSCATED_EVAL = /\b(?:eval|new\s+Function|Function)\s*\(\s*atob\(\s*["'`]([A-Za-z0-9+/=]{64,})["'`]\s*\)\s*\)/;

const LITERAL_BYPASS = /\b(password|passwd|token|secret|apiKey|role)\b\s*(?:===|==)\s*["'`]([^"'`]+)["'`]/i;
const SECRET_IDENT = /password|passwd|token|secret|apikey/i;

const AUTH_SKIP_IDENT = /\b(SKIP_AUTH|BYPASS_AUTH|DISABLE_AUTH|NO_AUTH)\b/;
const AUTH_SKIP_USAGE = new RegExp(
  `(if\\s*\\([^)]*${AUTH_SKIP_IDENT.source}[^)]*\\)|${AUTH_SKIP_IDENT.source}\\s*(?:\\|\\||&&)|(?:\\|\\||&&)\\s*${AUTH_SKIP_IDENT.source})`,
);

const ENV_DUMP = new RegExp(
  [
    "\\.\\.\\.process\\.env\\b",
    "JSON\\.stringify\\(\\s*process\\.env\\s*\\)",
    "(?:res\\.json|NextResponse\\.json|console\\.log)\\(\\s*process\\.env\\b",
  ].join("|"),
);

const OUTBOUND_CALL = /\b(?:fetch|axios(?:\.\w+)?|https?\.request)\s*\(\s*["'`](https?:\/\/[^"'`\s)]+)["'`]/g;

const OUTBOUND_ALLOWLIST = [
  "supabase.co", "stripe.com", "openai.com", "anthropic.com", "googleapis.com",
  "google.com", "github.com", "vercel.com", "sentry.io", "posthog.com",
  "resend.com", "amazonaws.com", "cloudflare.com", "twilio.com", "sendgrid.net",
  "mailgun.net", "slack.com", "discord.com", "notion.so", "hubspot.com", "api.clarity.ms",
];

function isAllowlistedHost(host: string): boolean {
  const h = host.toLowerCase();
  if (h === "localhost" || h === "127.0.0.1") return true;
  return OUTBOUND_ALLOWLIST.some((allowed) => h === allowed || h.endsWith(`.${allowed}`));
}

const PROMPT_INJECTION_ARTIFACT = /ignore\s+(?:all\s+)?previous\s+instructions|you are now|system prompt/i;

const check: Check = {
  name: "backdoor",
  description: "Finds obfuscated eval chains, hardcoded bypass conditionals, auth-skip flags, process.env dumps, unexpected outbound hosts, and prompt-injection artifacts left in generated code.",
  requires: [],
  async run(ctx: CheckContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const repoDir = ctx.repoDir ?? ".";
    const files = await getScanFiles(repoDir, ctx.changedFiles);

    for (const filePath of files) {
      const relPath = relative(repoDir, filePath).replace(/\\/g, "/");
      if (isSkippable(relPath)) continue;

      let text: string;
      try {
        const info = await stat(filePath);
        if (info.size > MAX_FILE_BYTES) continue;
        text = await readFile(filePath, "utf8");
      } catch {
        continue;
      }
      if (text.includes("\u0000")) continue;

      const lines = text.split("\n");
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const loc = `${relPath}:${i + 1}`;

        if (OBFUSCATED_EVAL.test(line)) {
          findings.push({
            id: "backdoor.obfuscated_eval",
            check: "backdoor",
            severity: "critical",
            title: "Obfuscated base64-eval chain",
            detail: "This line decodes a long base64 string and immediately runs it via eval/Function. This is the classic shape of hidden, obfuscated code: whatever it does is invisible to a code review.",
            location: loc,
            fix: "Remove the eval/Function(atob(...)) chain and replace it with plain, readable source. If this was generated by an AI agent, treat it as a compromise signal and audit the rest of the diff.",
          });
        }

        const literalMatch = line.match(LITERAL_BYPASS);
        if (literalMatch) {
          const ident = literalMatch[1];
          const critical = SECRET_IDENT.test(ident);
          findings.push({
            id: "backdoor.literal_bypass",
            check: "backdoor",
            severity: critical ? "critical" : "high",
            title: `Hardcoded bypass comparing ${ident} to a string literal`,
            detail: `This line grants or denies access by comparing "${ident}" to a hardcoded string literal ("${literalMatch[2]}"). This is a classic hidden backdoor or master-password pattern: anyone who reads the source (or the compiled bundle) can bypass real authentication.`,
            location: loc,
            fix: "Remove the literal comparison and check against a real credential store, session, or role table instead of a string baked into source.",
          });
        }

        if (AUTH_SKIP_USAGE.test(line)) {
          findings.push({
            id: "backdoor.auth_skip_flag",
            check: "backdoor",
            severity: "high",
            title: "Auth-skip flag short-circuits an authentication check",
            detail: "This line uses a SKIP_AUTH/BYPASS_AUTH/DISABLE_AUTH/NO_AUTH flag to short-circuit an authentication check. If this flag can be set in production (an env var, a misconfigured default), it disables auth entirely.",
            location: loc,
            fix: "Remove the auth-skip flag from any code path that can run in production, or gate it so it can only ever be true in local/test environments (and assert that at startup).",
          });
        }

        if (ENV_DUMP.test(line)) {
          findings.push({
            id: "backdoor.env_dump",
            check: "backdoor",
            severity: "high",
            title: "process.env dumped into a response or log",
            detail: "This line spreads or serializes the entire process.env object into a response, log, or console output. Every server secret (DB URLs, API keys, service_role keys) becomes visible to whoever can read that output.",
            location: loc,
            fix: "Never serialize process.env wholesale. Return only the specific, non-secret values the caller needs.",
          });
        }

        OUTBOUND_CALL.lastIndex = 0;
        for (const m of line.matchAll(OUTBOUND_CALL)) {
          let host: string;
          try {
            host = new URL(m[1]).hostname;
          } catch {
            continue;
          }
          if (isAllowlistedHost(host)) continue;
          findings.push({
            id: "backdoor.unexpected_outbound",
            check: "backdoor",
            severity: "medium",
            title: `Outbound call to unexpected host "${host}"`,
            detail: `This server code sends a request to "${host}", which is not one of the well-known providers keysnag recognises (Supabase, Stripe, OpenAI, Anthropic, Vercel, etc.). This may be legitimate, or it may be data exfiltration to a host slipped in by a compromised dependency or a malicious edit.`,
            location: loc,
            fix: `Verify this destination is intentional. If it is a legitimate third-party integration, ignore this warning; if not, remove the call and rotate any credentials it may have sent.`,
          });
        }

        if (PROMPT_INJECTION_ARTIFACT.test(line)) {
          findings.push({
            id: "backdoor.prompt_injection_artifact",
            check: "backdoor",
            severity: "medium",
            title: "Prompt-injection artifact left in source",
            detail: "This line contains text like \"ignore previous instructions\", \"you are now\", or \"system prompt\" inside application source, not a test fixture. This is either a leftover prompt-injection payload from an untrusted input, or an artifact of an AI agent that was manipulated while generating this code.",
            location: loc,
            fix: "Review how this string is used. If it is meant to defend against prompt injection, move it out of comments/dead code into an actual guard; if it is a leftover payload, remove it and audit how it got there.",
          });
        }
      }
    }

    return { check: check.name, ran: true, findings };
  },
};

export default check;
