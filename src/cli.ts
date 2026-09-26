#!/usr/bin/env node
// keysnag scan [--repo DIR] [--url URL] [--checks a,b] [--json] [--out FILE]
//              [--fail-on <info|low|medium|high|critical|off>] [--diff <ref>] [--no-osv]
// keysnag install [--pre-commit] [--repo DIR]
// keysnag uninstall [--repo DIR]
//
// `scan` findings are not process failures by themselves: the exit code is decided by
// gate.ts against --fail-on. `install`/`uninstall` exit 0 on success, 1 on a bad target.
import {
  writeFileSync,
  readFileSync,
  existsSync,
  unlinkSync,
  renameSync,
  chmodSync,
} from "node:fs";
import { resolve, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { Severity } from "./types.js";
import { loadContext, loadEnabledChecks, loadFailOnDefault } from "./config.js";
import { runChecks } from "./runner.js";
import { renderMarkdown, renderJson, renderAgentTasks } from "./report.js";
import { SEVERITIES, exitCodeForFindings, blockSummary } from "./gate.js";
import { loadAllowList, applyAllowList, appendAllowEntry } from "./allow.js";

const pexec = promisify(execFile);

const USAGE = [
  "usage:",
  "  keysnag scan [--repo DIR] [--url URL] [--checks a,b] [--json] [--out FILE]",
  "               [--fail-on <info|low|medium|high|critical|off>] [--diff <ref>] [--no-osv]",
  "  keysnag install [--pre-commit] [--repo DIR]",
  "  keysnag uninstall [--repo DIR]",
  '  keysnag allow <finding-id> <location> --reason "..." --bound "..." [--repo DIR]',
].join("\n");

interface ParsedFlags {
  command?: string;
  repo?: string;
  url?: string;
  checks?: string[];
  json: boolean;
  out?: string;
  failOn?: Severity | "off";
  diff?: string;
  noOsv: boolean;
  preCommit: boolean;
  allowFindingId?: string;
  allowLocation?: string;
  reason?: string;
  bound?: string;
}

function parseFailOn(value: string): Severity | "off" {
  if (value === "off" || (SEVERITIES as string[]).includes(value)) {
    return value as Severity | "off";
  }
  throw new Error(
    `invalid --fail-on value: "${value}" (expected info|low|medium|high|critical|off)`,
  );
}

function parseArgs(argv: string[]): ParsedFlags {
  const flags: ParsedFlags = { json: false, noOsv: false, preCommit: false };
  const [command, ...rest] = argv;
  flags.command = command;

  if (command === "allow") {
    const positionals: string[] = [];
    for (let i = 0; i < rest.length; i++) {
      const arg = rest[i];
      switch (arg) {
        case "--reason":
          flags.reason = rest[++i];
          break;
        case "--bound":
          flags.bound = rest[++i];
          break;
        case "--repo":
          flags.repo = rest[++i];
          break;
        default:
          if (arg.startsWith("--")) throw new Error(`unknown flag: ${arg}`);
          positionals.push(arg);
      }
    }
    flags.allowFindingId = positionals[0];
    flags.allowLocation = positionals[1];
    return flags;
  }

  for (let i = 0; i < rest.length; i++) {
    const arg = rest[i];
    switch (arg) {
      case "--repo":
        flags.repo = rest[++i];
        break;
      case "--url":
        flags.url = rest[++i];
        break;
      case "--checks":
        flags.checks = (rest[++i] ?? "")
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean);
        break;
      case "--json":
        flags.json = true;
        break;
      case "--out":
        flags.out = rest[++i];
        break;
      case "--fail-on":
        flags.failOn = parseFailOn(rest[++i] ?? "");
        break;
      case "--diff":
        flags.diff = rest[++i];
        break;
      case "--no-osv":
        flags.noOsv = true;
        break;
      case "--pre-commit":
        flags.preCommit = true;
        break;
      default:
        throw new Error(`unknown flag: ${arg}`);
    }
  }

  return flags;
}

async function computeChangedFiles(repoDir: string, ref: string): Promise<string[]> {
  const { stdout } = await pexec(
    "git",
    ["-C", repoDir, "diff", "--name-only", `${ref}...HEAD`],
    { maxBuffer: 64 * 1024 * 1024 },
  );
  return stdout
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean);
}

async function runAllow(flags: ParsedFlags): Promise<void> {
  if (!flags.allowFindingId || !flags.allowLocation) {
    console.error("keysnag: allow requires <finding-id> <location>");
    console.error(USAGE);
    process.exit(1);
  }
  const cwd = resolve(flags.repo ?? process.cwd());
  try {
    appendAllowEntry(cwd, {
      id: flags.allowFindingId,
      location: flags.allowLocation,
      reason: flags.reason ?? "",
      bound: flags.bound ?? "",
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(message);
    process.exit(1);
  }
  console.log(`keysnag: appended allow entry for "${flags.allowFindingId}" at "${flags.allowLocation}" to ${resolve(cwd, "keysnag.config.json")}`);
  process.exit(0);
}

async function runScan(flags: ParsedFlags): Promise<void> {
  const ctx = loadContext({ repoDir: flags.repo, siteUrl: flags.url });

  let allowEntries;
  try {
    allowEntries = loadAllowList(resolve(ctx.repoDir ?? process.cwd(), "keysnag.config.json"));
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(message);
    process.exit(1);
  }

  if (flags.diff) {
    try {
      ctx.changedFiles = await computeChangedFiles(ctx.repoDir ?? process.cwd(), flags.diff);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`keysnag: --diff failed to compute changed files (${message}); scanning full tree`);
    }
  }
  if (flags.noOsv) ctx.allowOsv = false;

  const failOn = flags.failOn ?? loadFailOnDefault();

  const enabled = loadEnabledChecks(flags.checks);
  const rawResults = await runChecks(ctx, enabled);
  const results = applyAllowList(rawResults, allowEntries);

  const outPath = flags.out ?? resolve(process.cwd(), "keysnag.report.md");
  writeFileSync(outPath, renderMarkdown(results), "utf8");

  if (flags.json) {
    const jsonPath = outPath.endsWith(".md")
      ? outPath.replace(/\.md$/, ".json")
      : `${outPath}.json`;
    writeFileSync(jsonPath, renderJson(results), "utf8");
    console.log(`wrote ${jsonPath}`);
  }

  console.log(`wrote ${outPath}`);
  console.log("");
  console.log(renderAgentTasks(results));

  const exitCode = exitCodeForFindings(results, failOn);
  if (exitCode !== 0) {
    console.error("");
    console.error(blockSummary(results, failOn));
  }
  process.exit(exitCode);
}

// --- install / uninstall ---------------------------------------------------

const HOOK_MARKER = "# keysnag-managed hook — see `keysnag uninstall`";

function resolveHooksDir(repoDir: string): string {
  return join(repoDir, ".git", "hooks");
}

function buildHookScript(kind: "pre-push" | "pre-commit"): string {
  const cliPath = fileURLToPath(import.meta.url);
  const prevName = `${kind}.keysnag-prev`;
  const scanArgs =
    kind === "pre-commit"
      ? "scan --checks secrets --fail-on critical"
      : "scan --fail-on critical";

  return `#!/bin/sh
${HOOK_MARKER}
# Installed by \`keysnag install${kind === "pre-commit" ? " --pre-commit" : ""}\`. Do not edit by hand; run \`keysnag uninstall\` to remove it.

PREV_HOOK="$(dirname "$0")/${prevName}"
if [ -x "$PREV_HOOK" ]; then
  "$PREV_HOOK" "$@"
  PREV_STATUS=$?
  if [ "$PREV_STATUS" -ne 0 ]; then
    exit "$PREV_STATUS"
  fi
fi

KEYSNAG_CLI="${cliPath}"
if [ -f "$KEYSNAG_CLI" ]; then
  node "$KEYSNAG_CLI" ${scanArgs}
else
  npx --no-install keysnag ${scanArgs}
fi
STATUS=$?
if [ -f "$(pwd)/keysnag.report.md" ]; then
  echo "keysnag report: $(pwd)/keysnag.report.md"
fi
exit $STATUS
`;
}

/** Writes a hook, chaining any pre-existing non-keysnag hook by renaming it to <name>.keysnag-prev. Idempotent. */
function installHook(hooksDir: string, name: "pre-push" | "pre-commit"): void {
  const hookPath = join(hooksDir, name);
  const prevPath = join(hooksDir, `${name}.keysnag-prev`);

  if (existsSync(hookPath)) {
    const existing = readFileSync(hookPath, "utf8");
    if (!existing.includes(HOOK_MARKER) && !existsSync(prevPath)) {
      renameSync(hookPath, prevPath);
      chmodSync(prevPath, 0o755);
    }
  }

  writeFileSync(hookPath, buildHookScript(name), "utf8");
  chmodSync(hookPath, 0o755);
}

/** Removes a keysnag-managed hook and restores any hook it had chained. Leaves non-keysnag hooks alone. */
function uninstallHook(hooksDir: string, name: "pre-push" | "pre-commit"): void {
  const hookPath = join(hooksDir, name);
  const prevPath = join(hooksDir, `${name}.keysnag-prev`);

  if (existsSync(hookPath)) {
    const content = readFileSync(hookPath, "utf8");
    if (!content.includes(HOOK_MARKER)) return; // not ours, leave it
    unlinkSync(hookPath);
  }

  if (existsSync(prevPath)) {
    renameSync(prevPath, hookPath);
    chmodSync(hookPath, 0o755);
  }
}

async function runInstall(flags: ParsedFlags): Promise<void> {
  const repoDir = resolve(flags.repo ?? process.cwd());
  const hooksDir = resolveHooksDir(repoDir);
  if (!existsSync(hooksDir)) {
    console.error(`keysnag: no .git/hooks directory found at ${hooksDir}. Run inside a git repo.`);
    process.exit(1);
  }

  installHook(hooksDir, "pre-push");
  console.log(`keysnag: installed pre-push hook at ${join(hooksDir, "pre-push")}`);

  if (flags.preCommit) {
    installHook(hooksDir, "pre-commit");
    console.log(`keysnag: installed pre-commit hook at ${join(hooksDir, "pre-commit")}`);
  }

  process.exit(0);
}

async function runUninstall(flags: ParsedFlags): Promise<void> {
  const repoDir = resolve(flags.repo ?? process.cwd());
  const hooksDir = resolveHooksDir(repoDir);
  if (!existsSync(hooksDir)) {
    console.error(`keysnag: no .git/hooks directory found at ${hooksDir}. Run inside a git repo.`);
    process.exit(1);
  }

  uninstallHook(hooksDir, "pre-push");
  uninstallHook(hooksDir, "pre-commit");
  console.log("keysnag: uninstalled");
  process.exit(0);
}

async function main(): Promise<void> {
  let flags: ParsedFlags;
  try {
    flags = parseArgs(process.argv.slice(2));
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`keysnag: ${message}`);
    console.error(USAGE);
    process.exit(1);
  }

  switch (flags.command) {
    case "scan":
      await runScan(flags);
      return;
    case "install":
      await runInstall(flags);
      return;
    case "uninstall":
      await runUninstall(flags);
      return;
    case "allow":
      await runAllow(flags);
      return;
    default:
      console.error(`keysnag: unknown command "${flags.command ?? ""}"`);
      console.error(USAGE);
      process.exit(1);
  }
}

main().catch((err) => {
  console.error(err instanceof Error ? err.stack ?? err.message : String(err));
  process.exit(1);
});
