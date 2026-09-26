// backdoor: hunts for deliberately or accidentally hidden covert-access code left by
// an AI coding agent: obfuscated eval chains, hardcoded bypass conditionals, auth-skip
// flags, process.env dumped to a response, exfiltration/tunnel outbound hosts, and stray
// prompt-injection artifacts. Repo-static only, requires: [].
import { readFile, readdir, stat } from "node:fs/promises";
import { join, relative, extname } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { Check, CheckContext, CheckResult, Finding } from "../types.js";
import { maskSecret } from "../types.js";

const pexec = promisify(execFile);

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", ".next", "build", ".claude"]);
const SKIP_EXTS = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".woff", ".woff2",
  ".ttf", ".eot", ".pdf", ".zip", ".gz", ".tgz", ".mp4", ".mov", ".mp3",
  ".wasm", ".node", ".lock", ".map",
]);
/** Only scan actual source code, per the calibration fix: never .md/.claude/docs. */
const SOURCE_EXTS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts"]);
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
  if (!SOURCE_EXTS.has(extname(norm))) return true;
  if (/\.(md|mdx|txt)$/.test(norm)) return true;
  if (norm.includes("/__tests__/") || norm.includes("/test/") || norm.includes("/tests/")) return true;
  if (/\.(test|spec)\.[jt]sx?$/.test(norm)) return true;
  if (norm.includes("/docs/") || norm.startsWith("docs/")) return true;
  if (norm.includes("/.claude/") || norm.startsWith(".claude/")) return true;
  return false;
}

const OBFUSCATED_EVAL = /\b(?:eval|new\s+Function|Function)\s*\(\s*atob\(\s*["'`]([A-Za-z0-9+/=]{64,})["'`]\s*\)\s*\)/;

// (B) calibration fix: role-literal comparisons (m.role === 'user', c.role === 'performance')
// are legitimate discriminated-union/enum checks, not backdoors. Fire only on an actual
// credential-shaped identifier compared to a string literal.
const LITERAL_BYPASS = /\b(password|passwd|pin|secret|masterKey|apiKey)\b\s*(?:===|==|!==|!=)\s*["'`]([^"'`]*)["'`]/i;

// (C4/precision calibration) `typeof x === "string"` and other typeof-guarded input
// validation idioms are not backdoors: the "literal" is a JS type name, not a
// credential. Same for an empty-string comparison (`token === ""`), which is a
// not-set check, not a hardcoded bypass.
const JS_TYPE_NAME = /^(?:string|number|boolean|undefined|object|function|symbol|bigint)$/i;

const AUTH_SKIP_IDENT = /\b(SKIP_AUTH|BYPASS_AUTH|DISABLE_AUTH|NO_AUTH)\b/;
const AUTH_SKIP_USAGE = new RegExp(
  `(if\\s*\\([^)]*${AUTH_SKIP_IDENT.source}[^)]*\\)|${AUTH_SKIP_IDENT.source}\\s*(?:\\|\\||&&)|(?:\\|\\||&&)\\s*${AUTH_SKIP_IDENT.source})`,
);

// (M) calibration fix: `const env = { ...parseEnvFile(p), ...process.env }` is a local
// merge, not a dump. Fire only when process.env is actually serialised or sent: passed to
// JSON.stringify, passed into a json response call, or logged.
// A single named property read (process.env.INTERNAL_JOB_KEY) is normal and must not
// match; only the whole process.env object, not one property off it, is a dump.
const WHOLE_PROCESS_ENV = "process\\.env\\b(?!\\s*[.\\[])";
const ENV_DUMP = new RegExp(
  [
    `JSON\\.stringify\\([^)]*${WHOLE_PROCESS_ENV}`,
    `(?:res\\.json|NextResponse\\.json|Response\\.json)\\([^)]*${WHOLE_PROCESS_ENV}`,
    `console\\.log\\(\\s*${WHOLE_PROCESS_ENV}\\s*\\)`,
  ].join("|"),
);

const OUTBOUND_CALL = /\b(?:fetch|axios(?:\.\w+)?|https?\.request)\s*\(\s*["'`](https?:\/\/[^"'`\s)]+)["'`]/g;

// (C) calibration fix: the provider allowlist approach flags every legitimate third-party
// integration (fal.run, api.perplexity.ai, api.amazon.com...) and misses real exfil hosts
// on the allowlist's blind side. Replace with a positive list of exfil/tunnel indicators.
const IP_LITERAL_HOST = /^(\d{1,3}\.){3}\d{1,3}$/;
const TUNNEL_HOST = /(ngrok|localtunnel|serveo|trycloudflare)/i;
const DEAD_DROP_HOST = /(pastebin|hastebin|webhook\.site|requestbin|pipedream\.net|beeceptor)/i;
const COLLABORATOR_HOST = /(burpcollaborator|interact\.sh|\boast\b)/i;
const SHORTENER_HOSTS = new Set(["bit.ly", "tinyurl.com", "t.co"]);

/** Best-effort: is this a client-side/browser file, where a Discord webhook or a
 * shortener call is a different (still worth-a-look, but not this check's) risk shape? */
function isClientFile(text: string, relPath: string): boolean {
  const head = text.slice(0, 400);
  if (/["'`]use client["'`]/.test(head)) return true;
  const norm = relPath.toLowerCase();
  return norm.includes("/components/") && !norm.includes("/api/");
}

function classifySuspiciousOutbound(
  hostname: string,
  pathname: string,
  relPath: string,
  clientFile: boolean,
): string | null {
  if (IP_LITERAL_HOST.test(hostname)) return `raw IP-literal host "${hostname}"`;
  if (TUNNEL_HOST.test(hostname)) return `tunnel/relay host "${hostname}"`;
  if (DEAD_DROP_HOST.test(hostname)) return `paste/dead-drop host "${hostname}"`;
  if (hostname === "api.telegram.org" && pathname.startsWith("/bot")) {
    return `Telegram bot API call "${hostname}${pathname}"`;
  }
  if (COLLABORATOR_HOST.test(hostname)) return `out-of-band collaborator host "${hostname}"`;
  if (hostname.endsWith(".onion")) return `Tor hidden-service host "${hostname}"`;

  const base = relPath.toLowerCase().split("/").pop() ?? "";
  const looksLikeNotifier = base.includes("notify") || base.includes("alert");
  if (!clientFile && !looksLikeNotifier && hostname === "discord.com" && pathname.startsWith("/api/webhooks")) {
    return `Discord webhook host "${hostname}${pathname}"`;
  }
  if (!clientFile && SHORTENER_HOSTS.has(hostname)) return `URL-shortener host "${hostname}"`;

  return null;
}

// (F) calibration fix: narrow to the actual attack phrase, and only inside a string
// literal (a comment saying "system prompt" or a docstring about "the assistant's system
// prompt" is not an injection artifact).
const PROMPT_INJECTION_PHRASE =
  /ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions|disregard\s+(?:all\s+)?(?:previous|prior)\s+instructions/i;
const PROMPT_INJECTION_ARTIFACT = new RegExp(
  `["'\`][^"'\`\\n]*(?:${PROMPT_INJECTION_PHRASE.source})[^"'\`\\n]*["'\`]`,
  "i",
);

const check: Check = {
  name: "backdoor",
  description: "Finds obfuscated eval chains, hardcoded bypass conditionals, auth-skip flags, process.env dumps, suspicious exfiltration/tunnel outbound hosts, and prompt-injection artifacts left in generated code.",
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

      const clientFile = isClientFile(text, relPath);
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
          const literal = literalMatch[2];
          const before = line.slice(0, literalMatch.index ?? 0);
          const isTypeofCheck = /\btypeof\s*$/.test(before);
          const isTypeName = JS_TYPE_NAME.test(literal);
          if (!isTypeofCheck && !isTypeName && literal !== "") {
            findings.push({
              id: "backdoor.literal_bypass",
              check: "backdoor",
              severity: "critical",
              title: `Hardcoded bypass comparing ${ident} to a string literal`,
              // C4: never put the raw hardcoded literal in any Finding field. Mask it.
              detail: `This line grants or denies access by comparing "${ident}" to a hardcoded string literal: a password/secret is compared to a hardcoded literal instead of a real credential store. This is a classic hidden backdoor or master-password pattern: anyone who reads the source (or the compiled bundle) can bypass real authentication.`,
              location: loc,
              evidence: maskSecret(literal),
              fix: "Remove the literal comparison and check against a real credential store, session, or role table instead of a string baked into source.",
            });
          }
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
            detail: "This line serialises or sends the entire process.env object into a response or console output. Every server secret (DB URLs, API keys, service_role keys) becomes visible to whoever can read that output.",
            location: loc,
            fix: "Never serialize process.env wholesale. Return only the specific, non-secret values the caller needs.",
          });
        }

        OUTBOUND_CALL.lastIndex = 0;
        for (const m of line.matchAll(OUTBOUND_CALL)) {
          let hostname: string;
          let pathname: string;
          try {
            const parsed = new URL(m[1]);
            hostname = parsed.hostname.toLowerCase();
            pathname = parsed.pathname;
          } catch {
            continue;
          }
          const why = classifySuspiciousOutbound(hostname, pathname, relPath, clientFile);
          if (!why) continue;
          findings.push({
            id: "backdoor.suspicious_outbound",
            check: "backdoor",
            severity: "high",
            title: `Outbound call to a suspicious host (${why})`,
            detail: `This server code sends a request to ${why}, which matches a known exfiltration or tunnelling pattern (raw IP literal, ngrok-style tunnel, paste/dead-drop site, bot/webhook relay, out-of-band collaborator, .onion, or URL shortener). This may be data exfiltration slipped in by a compromised dependency or a malicious edit.`,
            location: loc,
            fix: "Verify this destination is intentional and expected. If it is not, remove the call, rotate any credentials it may have sent, and audit how it got into the diff.",
          });
        }

        if (PROMPT_INJECTION_ARTIFACT.test(line)) {
          findings.push({
            id: "backdoor.prompt_injection_artifact",
            check: "backdoor",
            severity: "low",
            title: "Prompt-injection attack phrase left in a string literal",
            detail: "This line contains a string literal with a classic prompt-injection attack phrase (\"ignore previous instructions\", \"disregard prior instructions\"). This is either a leftover payload from an untrusted input that was captured into source, or an artifact of an AI agent that was manipulated while generating this code.",
            location: loc,
            fix: "Review how this string is used. If it is meant to defend against prompt injection, move it out of dead code into an actual guard; if it is a leftover payload, remove it and audit how it got there.",
          });
        }
      }
    }

    return { check: check.name, ran: true, findings };
  },
};

export default check;
