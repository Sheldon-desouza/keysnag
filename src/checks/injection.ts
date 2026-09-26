// injection: static, repo-aware scan for the T4 threat class (raw SQL concat, XSS
// sinks, eval/exec, SSRF, path traversal, prototype pollution). Regex/line-window
// heuristics, not an AST — Tier 2 documents the ts-morph upgrade. Reuses the
// git-aware getScanFiles pattern from secrets.ts so it only reads tracked files
// and honours ctx.changedFiles for --diff mode.
import { readFile, readdir, stat } from "node:fs/promises";
import { join, relative, extname } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { Check, CheckContext, CheckResult, Finding, Severity } from "../types.js";

const pexec = promisify(execFile);

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", ".next", "build", ".claude", ".vercel", "coverage", ".turbo", "out"]);

const SKIP_EXTS = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".woff", ".woff2",
  ".ttf", ".eot", ".pdf", ".zip", ".gz", ".tgz", ".mp4", ".mov", ".mp3",
  ".wasm", ".node", ".lock", ".map",
]);

// only worth reading as source
const SOURCE_EXTS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts"]);

const MAX_FILE_BYTES = 2 * 1024 * 1024;

// tokens that mark a value as coming from the incoming request, per the spec's
// "request-derived" definition.
const REQUEST_TOKEN = /\b(req\.|request\.|body\.|params\.|searchParams|query\.|headers\.|formData|cookies\()/;

/** repo-relative path checks: skip tests, fixtures, and .d.ts files. */
function isSkippablePath(relPath: string): boolean {
  const norm = relPath.replace(/\\/g, "/");
  if (norm.endsWith(".d.ts")) return true;
  const base = norm.split("/").pop() ?? "";
  if (/\.(test|spec)\./.test(base)) return true;
  if (norm.split("/").includes("__tests__")) return true;
  if (norm.includes("/fixture/") || norm.startsWith("fixture/")) return true;
  return false;
}

/**
 * Whether a token on `line`, or in the ~10 lines above it, looks request-derived:
 * either the request markers appear directly in the line, or a variable was
 * assigned from a request-derived expression within the backward window.
 */
function isRequestDerived(lines: string[], lineIdx: number): boolean {
  const line = lines[lineIdx];
  if (REQUEST_TOKEN.test(line)) return true;

  // simple backward scan: collect identifiers assigned from a request-derived
  // expression in the ~10 lines above, then see if the current line references one.
  const windowStart = Math.max(0, lineIdx - 10);
  const derivedIdents = new Set<string>();
  for (let i = windowStart; i < lineIdx; i++) {
    const assign = lines[i].match(/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=.*/);
    if (assign && REQUEST_TOKEN.test(lines[i])) {
      derivedIdents.add(assign[1]);
    }
  }
  if (derivedIdents.size === 0) return false;
  for (const ident of derivedIdents) {
    if (new RegExp(`\\b${ident}\\b`).test(line)) return true;
  }
  return false;
}

interface RawFinding {
  id: string;
  title: string;
  severity: Severity;
  detail: string;
  line: number;
  fix: string;
}

function scanText(text: string): RawFinding[] {
  const lines = text.split("\n");
  const found: RawFinding[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // --- injection.sql_concat ---
    // template literal or string concat piped into .rpc(/sql(/query(/execute(/raw(
    if (/\.(rpc|sql|query|execute|raw)\s*\(\s*(`[^`]*\$\{|["'][^"']*["']\s*\+|\+\s*["'])/.test(line)) {
      const derived = isRequestDerived(lines, i);
      found.push({
        id: "injection.sql_concat",
        title: "SQL built by string concatenation or template literal",
        severity: derived ? "critical" : "high",
        detail: "A SQL/RPC call is built from a template literal or string concatenation instead of a parameterised query, which allows SQL injection if any part of the value is attacker-controlled." + (derived ? " The value appears to come from the request." : ""),
        line: i + 1,
        fix: "Use a parameterised query or the query builder's bind parameters instead of interpolating values into the SQL string.",
      });
    }

    // --- injection.dangerous_html ---
    // dangerouslySetInnerHTML / innerHTML / outerHTML / insertAdjacentHTML fed by a non-literal
    const htmlMatch = line.match(/dangerouslySetInnerHTML\s*=\s*\{\{\s*__html:\s*([^}]+)\}\}/)
      || line.match(/\.(innerHTML|outerHTML)\s*=\s*([^;]+);?/)
      || line.match(/\.insertAdjacentHTML\s*\(\s*["'][^"']+["']\s*,\s*([^)]+)\)/);
    if (htmlMatch) {
      const value = (htmlMatch[2] ?? htmlMatch[1] ?? "").trim();
      const isLiteral = /^["'`][^"'`]*["'`]$/.test(value) || value === "";
      if (!isLiteral) {
        found.push({
          id: "injection.dangerous_html",
          title: "Raw HTML rendered from a non-literal value",
          severity: "high",
          detail: "HTML is injected via dangerouslySetInnerHTML/innerHTML/outerHTML/insertAdjacentHTML from a variable, which is a stored or reflected XSS sink if the value ever contains user input.",
          line: i + 1,
          fix: "Sanitise the HTML with a library such as DOMPurify before rendering, or render as plain text/React children instead of raw HTML.",
        });
      }
    }

    // --- injection.eval ---
    // eval(...) / new Function(...) / vm.runIn*(...). Skip the word "evaluate" and comments.
    const commentStripped = line.replace(/\/\/.*$/, "");
    if (/(?<!\w)eval\s*\(/.test(commentStripped.replace(/\bevaluate\b/g, ""))
      || /\bnew\s+Function\s*\(/.test(commentStripped)
      || /\bvm\.runIn\w*\s*\(/.test(commentStripped)) {
      const derived = isRequestDerived(lines, i);
      found.push({
        id: "injection.eval",
        title: "Dynamic code execution via eval/new Function/vm.runIn*",
        severity: derived ? "critical" : "high",
        detail: "Code is executed dynamically from a string, which allows arbitrary code execution if any part of that string is attacker-controlled." + (derived ? " The value appears to come from the request." : ""),
        line: i + 1,
        fix: "Remove the dynamic eval/new Function/vm.runIn* call; parse the input as data (JSON.parse) or use an explicit allowlisted dispatch instead of executing code.",
      });
    }

    // --- injection.command ---
    // exec/execSync/spawn with shell:true and interpolation, or exec/execSync with a
    // template literal / concatenated string (shell always on for exec/execSync).
    const cmdCall = line.match(/\b(exec|execSync|spawn|spawnSync)\s*\(/);
    if (cmdCall) {
      const fn = cmdCall[1];
      const hasInterp = /`[^`]*\$\{/.test(line) || /["'][^"']*["']\s*\+/.test(line);
      const isSpawnShell = (fn === "spawn" || fn === "spawnSync") && /shell\s*:\s*true/.test(line);
      const isExecFamily = fn === "exec" || fn === "execSync";
      if (hasInterp && (isExecFamily || isSpawnShell)) {
        const derived = isRequestDerived(lines, i);
        found.push({
          id: "injection.command",
          title: "Shell command built with string interpolation",
          severity: derived ? "critical" : "high",
          detail: `A shell command is built by interpolating a variable into ${fn}(), which allows command injection if any part of it is attacker-controlled.` + (derived ? " The value appears to come from the request." : ""),
          line: i + 1,
          fix: "Use execFile/spawn with an argument array (no shell:true) instead of building a shell command string, and never interpolate request data into a command string.",
        });
      }
    }

    // --- injection.ssrf ---
    // fetch/axios/got/http.get whose URL contains a request-derived token.
    const netCall = line.match(/\b(fetch|axios(?:\.\w+)?|got|https?\.get)\s*\(\s*([^,)]+)/);
    if (netCall) {
      const urlArg = netCall[2];
      if (REQUEST_TOKEN.test(urlArg) || isRequestDerived(lines, i)) {
        const hasGuard = /(startsWith|allowlist|allowList|ALLOWED_HOSTS|new URL\([^)]*\)\.hostname\s*===)/.test(
          lines.slice(Math.max(0, i - 5), i + 1).join("\n"),
        );
        found.push({
          id: "injection.ssrf",
          title: "Outbound request URL derived from the incoming request",
          severity: hasGuard ? "high" : "critical",
          detail: "A fetch/axios/got/http.get call builds its URL from request input with no visible host allowlist or guard, which allows server-side request forgery against internal services.",
          line: i + 1,
          fix: "Validate the target against an allowlist of hosts before fetching, or resolve to a fixed internal host and pass only a path/id, never a full attacker-supplied URL.",
        });
      }
    }

    // --- injection.path_traversal ---
    // path.join/resolve/readFile/createReadStream with request-derived input and no guard.
    const pathCall = line.match(/\b(path\.(?:join|resolve)|readFile(?:Sync)?|createReadStream)\s*\(([^)]*)\)/);
    if (pathCall) {
      const args = pathCall[2];
      if (REQUEST_TOKEN.test(args) || isRequestDerived(lines, i)) {
        const hasGuard = /(normalize|startsWith|allowlist|allowList|sanitiz)/.test(
          lines.slice(Math.max(0, i - 5), i + 1).join("\n"),
        );
        found.push({
          id: "injection.path_traversal",
          title: "File path built from request input",
          severity: hasGuard ? "high" : "critical",
          detail: "A file path is built from request input and passed to path.join/resolve/readFile/createReadStream with no visible normalize/startsWith/allowlist guard, which allows path traversal to read files outside the intended directory.",
          line: i + 1,
          fix: "Resolve the path, then verify it still starts with the intended base directory (path.normalize + startsWith), or map the request input to an allowlisted set of files instead of building a path from it directly.",
        });
      }
    }

    // --- injection.proto_pollution ---
    // Object.assign/spread of parsed request body into a config/options object, or
    // explicit __proto__ handling.
    if (/Object\.assign\s*\(\s*[^,]+,\s*[^)]*(?:body|req\.body|JSON\.parse)/.test(line)
      || /\{\s*\.\.\.(?:req\.body|body|JSON\.parse\([^)]*\))\s*\}/.test(line)
      || /__proto__/.test(line)) {
      found.push({
        id: "injection.proto_pollution",
        title: "Parsed request body merged into an object without guarding __proto__",
        severity: "medium",
        detail: "A parsed request body is spread or Object.assign'd into a config/options object. If the body contains a __proto__ or constructor.prototype key, this can pollute the prototype of every object in the process.",
        line: i + 1,
        fix: "Use a schema validator (zod) to parse the body into known fields only, or strip __proto__/constructor/prototype keys before merging, instead of spreading raw parsed JSON into an object.",
      });
    }
  }

  return found;
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

/** Same pattern as secrets.ts getScanFiles: git-aware, falls back to a walk. */
async function getScanFiles(repoDir: string, log: (msg: string) => void): Promise<string[]> {
  try {
    const { stdout } = await pexec(
      "git",
      ["-C", repoDir, "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
      { maxBuffer: 128 * 1024 * 1024 },
    );
    const rel = stdout.split("\u0000").filter(Boolean);
    if (rel.length === 0) return await walkRepo(repoDir);
    log(`injection: scanning ${rel.length} git-tracked/untracked files`);
    return rel.filter((r) => !SKIP_EXTS.has(extname(r))).map((r) => join(repoDir, r));
  } catch {
    log("injection: not a git repo, walking the filesystem");
    return await walkRepo(repoDir);
  }
}

async function scanRepo(repoDir: string, changedFiles: string[] | undefined, log: (msg: string) => void): Promise<Finding[]> {
  const findings: Finding[] = [];
  const seen = new Set<string>(); // dedup key: rule|file|line

  const files = changedFiles && changedFiles.length > 0
    ? changedFiles.map((f) => join(repoDir, f))
    : await getScanFiles(repoDir, log);

  for (const filePath of files) {
    const relPath = relative(repoDir, filePath);
    if (isSkippablePath(relPath)) continue;
    if (!SOURCE_EXTS.has(extname(filePath))) continue;

    let info;
    try {
      info = await stat(filePath);
    } catch {
      continue;
    }
    if (!info.isFile() || info.size > MAX_FILE_BYTES) continue;

    let text: string;
    try {
      text = await readFile(filePath, "utf8");
    } catch {
      continue;
    }
    if (text.includes("\u0000")) continue;

    for (const raw of scanText(text)) {
      const key = `${raw.id}|${relPath}|${raw.line}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push({
        id: raw.id,
        check: "injection",
        severity: raw.severity,
        title: raw.title,
        detail: raw.detail,
        location: `${relPath}:${raw.line}`,
        fix: raw.fix,
      });
    }
  }

  return findings;
}

const injectionCheck: Check = {
  name: "injection",
  description: "Static scan for SQL string concatenation, dangerous HTML sinks, eval/exec, SSRF, path traversal, and prototype pollution in repo-tracked source files.",
  requires: [],
  async run(ctx: CheckContext): Promise<CheckResult> {
    const repoDir = ctx.repoDir ?? ".";
    try {
      const findings = await scanRepo(repoDir, ctx.changedFiles, ctx.log);
      ctx.log(`injection: scanned repo at ${repoDir}, found ${findings.length} finding(s)`);
      return { check: "injection", ran: true, findings };
    } catch (err) {
      ctx.log(`injection: repo scan failed: ${(err as Error).message}`);
      return { check: "injection", ran: true, findings: [] };
    }
  },
};

export default injectionCheck;
