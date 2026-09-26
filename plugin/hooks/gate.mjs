#!/usr/bin/env node
// keysnag Claude Code hook: runs the same deterministic scan as the pre-push hook, on
// PostToolUse for `git commit`/`git push`. Never throws and never exits non-zero itself —
// blocking is communicated to Claude via the printed findings plus asyncRewake, not the
// process exit code, because a crashing hook would break Claude Code.
import { existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
// plugin/hooks/gate.mjs -> plugin/../dist/cli.js, i.e. the repo's own build output.
const localCli = join(here, "..", "..", "dist", "cli.js");

function runScan() {
  const args = ["scan", "--fail-on", "critical"];
  if (existsSync(localCli)) {
    return spawnSync("node", [localCli, ...args], { cwd: process.cwd(), encoding: "utf8" });
  }
  return spawnSync("npx", ["--no-install", "keysnag", ...args], {
    cwd: process.cwd(),
    encoding: "utf8",
  });
}

try {
  const result = runScan();
  const stdout = result.stdout ?? "";
  const stderr = result.stderr ?? "";
  console.log("## keysnag security gate");
  console.log("");
  if (stdout.trim()) console.log(stdout.trim());
  if (stderr.trim()) console.log(stderr.trim());
  if (result.error) {
    console.log(`(keysnag could not run: ${result.error.message})`);
  }
} catch (err) {
  console.log(`(keysnag hook failed unexpectedly: ${err instanceof Error ? err.message : String(err)})`);
}

// Always exit 0: blocking is communicated through the printed findings and asyncRewake,
// never by failing this hook itself.
process.exit(0);
