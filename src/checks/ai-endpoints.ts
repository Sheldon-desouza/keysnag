// ai-endpoints: LLM SDK calls made from a client component, server routes that call an
// LLM with no auth or rate limit, and prompts built directly from raw request input.
// Repo-static only, requires: [].
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

function isSkippable(relPath: string): boolean {
  const norm = relPath.replace(/\\/g, "/").toLowerCase();
  if (/\.(md|mdx)$/.test(norm)) return true;
  if (norm.includes("/__tests__/") || norm.includes("/test/") || norm.includes("/tests/")) return true;
  if (/\.(test|spec)\.[jt]sx?$/.test(norm)) return true;
  if (norm.includes("/docs/")) return true;
  return false;
}

const LLM_IMPORT = /from\s+["'](openai|@anthropic-ai\/sdk|@google\/generative-ai|ai|groq-sdk|cohere-ai|@mistralai)["']|require\(\s*["'](openai|@anthropic-ai\/sdk|@google\/generative-ai|ai|groq-sdk|cohere-ai|@mistralai)["']\s*\)/;
const LLM_URL = /api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com/;

const AUTH_SIGNAL = /getUser\(|getSession\(|auth\(\)|getServerSession\(|requireAuth|withAuth|authorization/i;

// A route is "spend-bounded" if it has a rate limiter, a credit/quota/plan gate,
// an admin gate, or a cron/internal shared-secret check. Any one of these stops
// a single caller from looping an LLM call unboundedly.
const SPEND_BOUND_SIGNAL =
  /ratelimit|rateLimit|limiter|upstash|@arcjet|slidingWindow|tokenBucket|checkRateLimit|checkSpendLimit|consumeSpendLimit|checkAndDeductCredit|deductCredit|\bcredits\b|\bquota\b|requirePlan|hasPlan|subscription|requireAdmin|isAdmin|CRON_SECRET|x-cron-secret|Bearer\s*\$?\{?\s*process\.env/i;

const SANITIZER_SIGNAL = /DOMPurify|sanitize-html|sanitizeHtml|rehype-sanitize/;
const UNSAFE_RENDER_CALL = /(dangerouslySetInnerHTML|\.innerHTML\s*=|insertAdjacentHTML\s*\(|\bmarked\s*\(|markdown-it|remark-html)/;
const LLM_RESULT_ASSIGN = /\b(\w+)\s*=\s*(?:await\s+)?[\w$.]*\.(?:chat\.completions\.create|completions\.create|messages\.create|generateText|streamText)\s*\(/g;
const LLM_RESULT_NAMES = ["reply", "answer", "completion", "aiResponse", "llmOutput"];

/** Identifiers that plausibly hold raw LLM output text: assigned from a known
 * completion call, or named like one of the conventional result variables. */
function collectLlmOutputIdents(text: string): Set<string> {
  const idents = new Set<string>();
  LLM_RESULT_ASSIGN.lastIndex = 0;
  for (const m of text.matchAll(LLM_RESULT_ASSIGN)) idents.add(m[1]);
  for (const name of LLM_RESULT_NAMES) {
    if (new RegExp(`\\b${name}\\b`, "i").test(text)) idents.add(name);
  }
  return idents;
}

const NEXT_PUBLIC_KEY = /NEXT_PUBLIC_[A-Z0-9_]*(?:OPENAI|ANTHROPIC|LLM|AI)[A-Z0-9_]*/;
const USE_CLIENT_DIRECTIVE = /^\s*["']use client["'];?\s*$/m;

function isRouteFile(relPath: string): boolean {
  const norm = relPath.replace(/\\/g, "/");
  return /\/api\//.test(norm) || /route\.(ts|tsx|js|jsx)$/.test(norm) || /^app\//.test(norm) && /route\.(ts|tsx|js|jsx)$/.test(norm) || /pages\/api\//.test(norm);
}

// prompt/messages content built directly from request-derived input with no
// template literal or guard function wrapping it.
const RAW_PROMPT = /\b(prompt|content|messages)\s*:\s*(?:await\s+)?(body|req\.body|params|searchParams)\.\w+(?!\s*[`(])/;

const check: Check = {
  name: "ai-endpoints",
  description: "Finds LLM SDK calls made from client components, server routes that call an LLM with no auth or rate limit, and prompts built directly from raw request input.",
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

      const hasLlmSignal = LLM_IMPORT.test(text) || LLM_URL.test(text);
      if (!hasLlmSignal) continue;

      const isClient = USE_CLIENT_DIRECTIVE.test(text);
      const hasNextPublicKey = NEXT_PUBLIC_KEY.test(text);

      if (isClient || hasNextPublicKey) {
        const firstLine = text.split("\n").findIndex((l) => LLM_IMPORT.test(l) || LLM_URL.test(l));
        findings.push({
          id: "ai.llm_call_in_client",
          check: "ai-endpoints",
          severity: "critical",
          title: "LLM SDK/API called from client-reachable code",
          detail: isClient
            ? "This file is a client component (\"use client\") and calls an LLM SDK/API directly. Any API key it uses ships to every visitor's browser and can be stolen from the bundle."
            : "This file references a NEXT_PUBLIC_* environment variable alongside an LLM SDK/API call, which ships the key to the browser bundle.",
          location: `${relPath}:${(firstLine >= 0 ? firstLine : 0) + 1}`,
          fix: "Move the LLM call into a server-only route or server action. Never construct an LLM client with a key read from a NEXT_PUBLIC_* variable or from client-side code.",
        });
      }

      let noAuth = false;
      if (isRouteFile(relPath) && !isClient) {
        noAuth = !AUTH_SIGNAL.test(text);
        if (noAuth) {
          findings.push({
            id: "ai.llm_route_no_auth",
            check: "ai-endpoints",
            severity: "high",
            title: "LLM route has no auth check",
            detail: "This server route calls an LLM SDK/API but never checks the caller's session or identity, so anyone who finds the URL can run it and rack up usage on your API key.",
            location: `${relPath}:1`,
            fix: "Require an authenticated session (e.g. getUser()/getServerSession()) before making the LLM call, and reject unauthenticated requests with 401.",
          });
        }
        if (!SPEND_BOUND_SIGNAL.test(text)) {
          findings.push({
            id: "ai.llm_route_no_spend_bound",
            check: "ai-endpoints",
            severity: noAuth ? "critical" : "high",
            title: "LLM route has no spend bound",
            detail: "This server route calls an LLM SDK/API with no rate limit, credit/quota/plan gate, admin gate, or cron/internal secret check. An unbounded LLM route lets one logged-in user run up your API bill in a loop.",
            location: `${relPath}:1`,
            fix: "Add a rate limiter (e.g. Upstash ratelimit, @arcjet) or a credit/quota check (e.g. checkAndDeductCredit) in front of the LLM call, keyed by user or IP.",
          });
        }
      }

      const lines = text.split("\n");
      for (let i = 0; i < lines.length; i++) {
        if (RAW_PROMPT.test(lines[i])) {
          findings.push({
            id: "ai.raw_user_prompt",
            check: "ai-endpoints",
            severity: "low",
            title: "Prompt built directly from raw request input",
            detail: "This line passes request body/params/searchParams straight into a prompt/content/messages field with no template, delimiter, or sanitization, making prompt injection from user input trivial.",
            location: `${relPath}:${i + 1}`,
            fix: "Wrap user input in a clearly delimited template (e.g. a labelled block) and validate/sanitize it before it reaches the model, rather than splicing raw request data straight into the prompt.",
          });
        }
      }
    }

    // ai.unsafe_output_render: scan every file independently of the LLM-call gate
    // above, since the render can happen in a different (client) file from the call.
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
      if (!UNSAFE_RENDER_CALL.test(text)) continue;

      const idents = collectLlmOutputIdents(text);
      if (idents.size === 0) continue;
      if (SANITIZER_SIGNAL.test(text)) continue;

      // The identifier check above already established this file both holds an
      // LLM-output-shaped variable and has no sanitiser signal anywhere; report
      // at the first line that renders something as HTML.
      const lines = text.split("\n");
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (!UNSAFE_RENDER_CALL.test(line)) continue;
        findings.push({
          id: "ai.unsafe_output_render",
          check: "ai-endpoints",
          severity: "high",
          title: "LLM output rendered as HTML with no sanitiser",
          detail: "Raw text from an LLM response is rendered via dangerouslySetInnerHTML/innerHTML/insertAdjacentHTML, or converted from markdown with marked()/markdown-it/remark-html, with no sanitiser (DOMPurify/sanitize-html/rehype-sanitize) anywhere in this file. A model output that echoes or is steered by user input (prompt injection) can inject script into the page.",
          location: `${relPath}:${i + 1}`,
          fix: "Sanitise the LLM output before rendering it as HTML, e.g. DOMPurify.sanitize(html), or render it as plain text instead of HTML.",
        });
        break;
      }
    }

    return { check: check.name, ran: true, findings };
  },
};

export default check;
