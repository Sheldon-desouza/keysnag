#!/usr/bin/env node
// keysnag scan [--repo DIR] [--url URL] [--checks a,b] [--json] [--out FILE]
// Findings are not process failures: this always exits 0 unless the flags themselves are malformed.
import { writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { loadContext, loadEnabledChecks } from "./config.js";
import { runChecks } from "./runner.js";
import { renderMarkdown, renderJson, renderAgentTasks } from "./report.js";

interface ParsedFlags {
  command?: string;
  repo?: string;
  url?: string;
  checks?: string[];
  json: boolean;
  out?: string;
}

function parseArgs(argv: string[]): ParsedFlags {
  const flags: ParsedFlags = { json: false };
  const [command, ...rest] = argv;
  flags.command = command;

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
      default:
        throw new Error(`unknown flag: ${arg}`);
    }
  }

  return flags;
}

async function main(): Promise<void> {
  let flags: ParsedFlags;
  try {
    flags = parseArgs(process.argv.slice(2));
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`keysnag: ${message}`);
    console.error("usage: keysnag scan [--repo DIR] [--url URL] [--checks a,b] [--json] [--out FILE]");
    process.exit(1);
  }

  if (flags.command !== "scan") {
    console.error(`keysnag: unknown command "${flags.command ?? ""}"`);
    console.error("usage: keysnag scan [--repo DIR] [--url URL] [--checks a,b] [--json] [--out FILE]");
    process.exit(1);
  }

  const ctx = loadContext({ repoDir: flags.repo, siteUrl: flags.url });
  const enabled = loadEnabledChecks(flags.checks);
  const results = await runChecks(ctx, enabled);

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

  process.exit(0);
}

main().catch((err) => {
  console.error(err instanceof Error ? err.stack ?? err.message : String(err));
  process.exit(1);
});
