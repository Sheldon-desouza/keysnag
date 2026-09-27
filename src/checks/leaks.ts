// leaks — "is this repo safe to make public?" Finds the non-secret things that should
// not ship in a public repo: your local home-directory paths, names you have told
// keysnag are private (a client, an employer, an internal project), internal
// scaffolding files, and the same names in commit messages and old history.
//
// Private terms come from a gitignored `.keysnag-private` file (one term per line,
// `#` comments) and/or KEYSNAG_PRIVATE_TERMS (comma-separated). Never from
// keysnag.config.json: that file is usually committed, and the list would leak itself.
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { readFileSync, existsSync, statSync } from "node:fs";
import { join } from "node:path";
import type { Check, CheckContext, CheckResult, Finding } from "../types.js";

const pexec = promisify(execFile);
const MAX_BYTES = 2 * 1024 * 1024;
export const PRIVATE_TERMS_FILE = ".keysnag-private";

// Home-directory paths. The name group is what leaks.
const LOCAL_PATH_RE = /(?:\/(?:Users|home)\/|[A-Za-z]:\\\\?Users\\\\?)([A-Za-z0-9._-]{2,40})(?=[\/\\])/g;
// Names that are placeholders or CI accounts, not a real person.
const PLACEHOLDER_NAMES = new Set([
  "user", "username", "you", "your-name", "yourname", "me", "name", "runner", "node",
  "ubuntu", "vscode", "codespace", "codespaces", "shared", "example", "someone", "admin",
  "root", "circleci", "travis", "jenkins", "docker", "app", "dev", "developer", "linuxbrew",
]);

// Tracked paths that are local scaffolding, not source.
const INTERNAL_PATHS: { re: RegExp; what: string; severity: Finding["severity"] }[] = [
  { re: /(^|\/)\.vercel\//, what: "a Vercel project link (.vercel/ holds your project and team ids)", severity: "medium" },
  { re: /(^|\/)\.workflow\//, what: "an agent workflow folder (.workflow/ holds plans, ledgers and scratch notes)", severity: "medium" },
  { re: /(^|\/)\.claude\/settings\.local\.json$/, what: "local Claude Code settings (settings.local.json is per-machine)", severity: "medium" },
  { re: /(^|\/)\.claude\/.*\.jsonl$/, what: "an AI chat transcript", severity: "high" },
  { re: /(^|\/)\.keysnag-private$/, what: "your private-terms list itself", severity: "high" },
  { re: /(^|\/)\.DS_Store$/, what: "a macOS folder metadata file", severity: "low" },
];

async function git(repoDir: string, args: string[]): Promise<string | undefined> {
  try {
    const { stdout } = await pexec("git", ["-C", repoDir, ...args], { maxBuffer: 256 * 1024 * 1024, timeout: 60_000 });
    return stdout;
  } catch {
    return undefined;
  }
}

export function loadPrivateTerms(repoDir: string, fromEnv?: string[]): string[] {
  const terms = new Set<string>();
  for (const t of fromEnv ?? []) if (t.trim().length >= 3) terms.add(t.trim());
  const file = join(repoDir, PRIVATE_TERMS_FILE);
  if (existsSync(file)) {
    for (const raw of readFileSync(file, "utf8").split("\n")) {
      const line = raw.trim();
      if (line.length >= 3 && !line.startsWith("#")) terms.add(line);
    }
  }
  return [...terms];
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** A term matches case-insensitively, and not as part of a longer word. */
function termRegex(term: string): RegExp {
  return new RegExp(`(?<![A-Za-z0-9])${escapeRe(term)}(?![A-Za-z0-9])`, "i");
}

/** Show the term in context, clipped, so the report proves the hit without dumping the file. */
function snippet(line: string, at: number): string {
  const start = Math.max(0, at - 40);
  const s = line.slice(start, at + 60).trim();
  return (start > 0 ? "…" : "") + s + (at + 60 < line.length ? "…" : "");
}

const leaks: Check = {
  name: "leaks",
  description:
    "Before a repo goes public: local home paths, private names you list (client, employer, internal project), internal scaffolding files, and those names in commit messages and history.",
  requires: ["repoDir"],
  async run(ctx: CheckContext): Promise<CheckResult> {
    const repoDir = ctx.repoDir!;
    const findings: Finding[] = [];
    const terms = loadPrivateTerms(repoDir, ctx.privateTerms);
    const termRes = terms.map((t) => ({ term: t, re: termRegex(t) }));

    const listed = await git(repoDir, ["ls-files", "--cached", "-z"]);
    if (listed === undefined) {
      return {
        check: "leaks",
        ran: false,
        skippedReason: "not a git repo (leaks checks what git would publish)",
        findings: [],
      };
    }
    let files = listed.split("\0").filter(Boolean);
    if (ctx.changedFiles) {
      const changed = new Set(ctx.changedFiles);
      files = files.filter((f) => changed.has(f));
    }

    // 1. Internal scaffolding files that are tracked.
    for (const f of files) {
      const hit = INTERNAL_PATHS.find((p) => p.re.test(f));
      if (!hit) continue;
      findings.push({
        id: "leaks.internal_file",
        check: "leaks",
        severity: hit.severity,
        title: `Tracked file is ${hit.what}`,
        detail: "This file is committed, so anyone who can see the repo can read it. It is local working state, not part of what you are publishing.",
        location: f,
        fix: `Run \`git rm --cached ${f}\`, add it to .gitignore, and commit. If the repo is or was public, it also stays in history until you rewrite it.`,
      });
    }

    // 2. File contents: local paths and private terms.
    const pathHits = new Map<string, string[]>(); // name -> locations
    for (const f of files) {
      if (/(^|\/)\.keysnag-private$/.test(f)) continue;
      const abs = join(repoDir, f);
      let text: string;
      try {
        if (statSync(abs).size > MAX_BYTES) continue;
        const buf = readFileSync(abs);
        if (buf.subarray(0, 8192).includes(0)) continue; // binary
        text = buf.toString("utf8");
      } catch {
        continue;
      }
      const lines = text.split("\n");
      lines.forEach((line, i) => {
        LOCAL_PATH_RE.lastIndex = 0;
        for (const m of line.matchAll(LOCAL_PATH_RE)) {
          const name = m[1];
          if (PLACEHOLDER_NAMES.has(name.toLowerCase()) || name.startsWith("$") || name.startsWith("<")) continue;
          const locs = pathHits.get(name) ?? [];
          locs.push(`${f}:${i + 1}`);
          pathHits.set(name, locs);
        }
        for (const { term, re } of termRes) {
          const m = re.exec(line);
          if (!m) continue;
          findings.push({
            id: "leaks.private_term",
            check: "leaks",
            severity: "high",
            title: `Private name "${term}" appears in a tracked file`,
            detail: "You listed this name as private. It is in a file that ships with the repo, so making the repo public publishes it.",
            location: `${f}:${i + 1}`,
            evidence: snippet(line, m.index),
            fix: "Replace it with a generic example (or delete the line) and commit. The old version stays in git history until you rewrite it.",
          });
        }
      });
    }
    for (const [name, locs] of pathHits) {
      findings.push({
        id: "leaks.local_path",
        check: "leaks",
        severity: "medium",
        title: `Local home-directory path with username "${name}"`,
        detail: `An absolute path from your machine is committed in ${locs.length} place(s). It exposes your username and folder layout, and it breaks on anyone else's machine.`,
        location: locs[0],
        evidence: locs.slice(0, 5).join(", ") + (locs.length > 5 ? `, +${locs.length - 5} more` : ""),
        fix: "Make the path relative to the repo (for tests, resolve it from import.meta.url or __dirname), or use a placeholder like /Users/you/.",
      });
    }

    // 3 and 4. Commit messages, author lines and history. Skipped in pre-push diff mode,
    // where only the files being pushed are in scope.
    if (!ctx.changedFiles && termRes.length > 0) {
      const log = await git(repoDir, ["log", "--all", "--format=%h%x00%an <%ae>%x00%B%x1e"]);
      for (const { term, re } of termRes) {
        const shas: string[] = [];
        for (const rec of (log ?? "").split("\x1e")) {
          const [sha, author, body] = rec.replace(/^\n/, "").split("\0");
          if (sha && (re.test(body ?? "") || re.test(author ?? ""))) shas.push(sha);
        }
        if (shas.length > 0) {
          findings.push({
            id: "leaks.private_term_in_commits",
            check: "leaks",
            severity: "high",
            title: `Private name "${term}" appears in ${shas.length} commit message(s) or author line(s)`,
            detail: "Commit messages and author names are public the moment the repo is. Fixing files does not change them.",
            location: `commits ${shas.slice(0, 5).join(", ")}${shas.length > 5 ? ` +${shas.length - 5} more` : ""}`,
            fix: "Rewrite the messages before going public (git filter-repo --message-callback, or rebase -i and reword). On an already-public repo this needs a force-push, so treat it as a deliberate decision.",
          });
        }
        const hist = await git(repoDir, ["log", "--all", "-i", "--pickaxe-regex", `-S${escapeRe(term)}`, "--format=%h"]);
        const histShas = (hist ?? "").split("\n").filter(Boolean);
        if (histShas.length > 0) {
          findings.push({
            id: "leaks.private_term_in_history",
            check: "leaks",
            severity: "high",
            title: `Private name "${term}" was added or removed in ${histShas.length} commit(s) of file history`,
            detail: "Even if today's files are clean, every old version of every file is downloadable from a public repo.",
            location: `commits ${histShas.slice(0, 5).join(", ")}${histShas.length > 5 ? ` +${histShas.length - 5} more` : ""}`,
            fix: "Rewrite history with git filter-repo --replace-text before going public. If it is already public, rotate anything sensitive, rewrite, force-push, and assume forks and caches kept a copy.",
          });
        }
      }
    }

    if (termRes.length === 0) {
      ctx.log(`leaks: no private terms configured. Add names to a gitignored ${PRIVATE_TERMS_FILE} (one per line) or KEYSNAG_PRIVATE_TERMS to check for them.`);
    }
    return { check: "leaks", ran: true, findings };
  },
};

export default leaks;
