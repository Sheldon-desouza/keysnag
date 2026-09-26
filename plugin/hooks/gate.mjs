#!/usr/bin/env node
// keysnag Claude Code hook: runs the same deterministic scan as the pre-push hook, on
// PostToolUse for `git commit`/`git push`. Prints the findings (including the agent-task
// block) and, per the asyncRewake protocol Claude Code uses (see security-guidance's
// hooks/security_reminder_hook.py around lines 1489-1493), exits 2 when the scan reports
// one or more blocking (critical) findings so Claude is woken with them. Exits 0 when
// clean. Never exits non-zero on a spawn/tool error: a crashing hook must not break
// Claude Code, so a missing/broken keysnag install just prints a one-line note and
// exits 0.
import { existsSync, readFileSync, rmSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";

const here = dirname(fileURLToPath(import.meta.url));
// plugin/hooks/gate.mjs -> plugin/../dist/cli.js, i.e. the repo's own build output.
const localCli = join(here, "..", "..", "dist", "cli.js");

/** The CLI to run, overridable for tests via KEYSNAG_CLI (an executable script path). */
function resolveCli() {
  if (process.env.KEYSNAG_CLI) {
    return { cmd: process.env.KEYSNAG_CLI, args: [] };
  }
  if (existsSync(localCli)) {
    return { cmd: "node", args: [localCli] };
  }
  return { cmd: "npx", args: ["--no-install", "keysnag"] };
}

function runScan() {
  const { cmd, args: baseArgs } = resolveCli();
  const base = join(tmpdir(), `keysnag-gate-${process.pid}-${randomUUID()}`);
  const mdPath = `${base}.md`;
  const jsonPath = `${base}.json`;
  const args = [...baseArgs, "scan", "--fail-on", "critical", "--json", "--out", mdPath];
  const result = spawnSync(cmd, args, { cwd: process.cwd(), encoding: "utf8" });
  return { result, jsonPath, mdPath };
}

/** Counts critical findings, preferring the JSON report keysnag wrote (most reliable), and
 * falling back to a "N critical" summary line in stdout/stderr (covers a stub or a keysnag
 * build that ignored --json). Never throws: an unreadable/malformed report just yields 0. */
function countCritical(result, jsonPath) {
  if (jsonPath && existsSync(jsonPath)) {
    try {
      const data = JSON.parse(readFileSync(jsonPath, "utf8"));
      const results = Array.isArray(data) ? data : [];
      const findings = results.flatMap((r) => (Array.isArray(r?.findings) ? r.findings : []));
      return findings.filter((f) => f?.severity === "critical").length;
    } catch {
      // fall through to text parsing
    }
  }
  const text = `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
  const match = text.match(/(\d+)\s*critical/i);
  return match ? Number(match[1]) : 0;
}

function cleanup(...paths) {
  for (const p of paths) {
    try {
      if (existsSync(p)) rmSync(p);
    } catch {
      // best effort
    }
  }
}

let exitCode = 0;
try {
  const { result, jsonPath, mdPath } = runScan();
  const stdout = (result.stdout ?? "").trim();
  const stderr = (result.stderr ?? "").trim();

  console.log("## keysnag security gate");
  console.log("");
  if (stdout) console.log(stdout);
  if (stderr) console.log(stderr);

  if (result.error) {
    console.log(`(keysnag could not run: ${result.error.message})`);
    exitCode = 0;
  } else {
    const critical = countCritical(result, jsonPath);
    exitCode = critical > 0 ? 2 : 0;
  }

  cleanup(jsonPath, mdPath);
} catch (err) {
  console.log(`(keysnag hook failed unexpectedly: ${err instanceof Error ? err.message : String(err)})`);
  exitCode = 0;
}

process.exit(exitCode);
