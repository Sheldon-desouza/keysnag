// Loads a CheckContext from CLI overrides, env vars, keysnag.config.json, and a local .env.
// Precedence, highest first: CLI flags (passed in as `overrides`) > env vars > keysnag.config.json.
import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import type { CheckContext, Check, Severity } from "./types.js";
import { checks as registry } from "./checks/index.js";
import { SEVERITIES } from "./gate.js";

/** Minimal .env parser: KEY=VALUE per line, `#` comments, no interpolation, no quoting rules beyond strip. */
function parseEnvFile(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const rawLine of text.split("\n")) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq === -1) continue;
    const key = line.slice(0, eq).trim();
    let value = line.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    out[key] = value;
  }
  return out;
}

function loadDotEnv(cwd: string): Record<string, string> {
  const path = resolve(cwd, ".env");
  if (!existsSync(path)) return {};
  try {
    return parseEnvFile(readFileSync(path, "utf8"));
  } catch {
    return {};
  }
}

interface KeysnagConfigFile {
  repoDir?: string;
  siteUrl?: string;
  supabaseUrl?: string;
  supabaseAnonKey?: string;
  pgUrl?: string;
  tokenA?: string;
  tokenB?: string;
  checks?: string[];
}

function loadConfigFile(cwd: string): KeysnagConfigFile {
  const path = resolve(cwd, "keysnag.config.json");
  if (!existsSync(path)) return {};
  try {
    return JSON.parse(readFileSync(path, "utf8")) as KeysnagConfigFile;
  } catch {
    return {};
  }
}

export interface ContextOverrides {
  repoDir?: string;
  siteUrl?: string;
  supabaseUrl?: string;
  supabaseAnonKey?: string;
  pgUrl?: string;
  tokenA?: string;
  tokenB?: string;
  allowOsv?: boolean;
  log?: (msg: string) => void;
  cwd?: string;
}

/**
 * Builds a CheckContext. Precedence per field, highest first:
 * 1. `overrides` (CLI flags)
 * 2. env vars (KEYSNAG_REPO_DIR, KEYSNAG_SITE_URL, KEYSNAG_SUPABASE_URL, KEYSNAG_SUPABASE_ANON_KEY, KEYSNAG_PG_URL, KEYSNAG_TOKEN_A, KEYSNAG_TOKEN_B)
 * 3. keysnag.config.json in cwd
 * A local .env (simple parser, no dotenv dep) is merged into process.env lookups at the same
 * precedence as real env vars, without overwriting a real env var that is already set.
 */
export function loadContext(overrides: ContextOverrides = {}): CheckContext {
  const cwd = overrides.cwd ?? process.cwd();
  const dotEnv = loadDotEnv(cwd);
  const config = loadConfigFile(cwd);

  const envOrDotEnv = (key: string): string | undefined =>
    process.env[key] ?? dotEnv[key];

  return {
    repoDir:
      overrides.repoDir ?? envOrDotEnv("KEYSNAG_REPO_DIR") ?? config.repoDir,
    siteUrl:
      overrides.siteUrl ?? envOrDotEnv("KEYSNAG_SITE_URL") ?? config.siteUrl,
    supabaseUrl:
      overrides.supabaseUrl ??
      envOrDotEnv("KEYSNAG_SUPABASE_URL") ??
      config.supabaseUrl,
    supabaseAnonKey:
      overrides.supabaseAnonKey ??
      envOrDotEnv("KEYSNAG_SUPABASE_ANON_KEY") ??
      config.supabaseAnonKey,
    pgUrl: overrides.pgUrl ?? envOrDotEnv("KEYSNAG_PG_URL") ?? config.pgUrl,
    tokenA: overrides.tokenA ?? envOrDotEnv("KEYSNAG_TOKEN_A") ?? config.tokenA,
    tokenB: overrides.tokenB ?? envOrDotEnv("KEYSNAG_TOKEN_B") ?? config.tokenB,
    allowOsv: overrides.allowOsv ?? parseAllowOsv(envOrDotEnv("KEYSNAG_ALLOW_OSV")),
    privateTerms: parseList(envOrDotEnv("KEYSNAG_PRIVATE_TERMS")),
    log: overrides.log ?? ((msg: string) => console.error(msg)),
  };
}

/** Comma-separated list, trimmed, empties dropped. */
function parseList(value: string | undefined): string[] | undefined {
  if (!value) return undefined;
  const out = value.split(",").map((s) => s.trim()).filter(Boolean);
  return out.length ? out : undefined;
}

/** KEYSNAG_ALLOW_OSV="false" disables the one third-party call (OSV.dev). Anything else, or unset, allows it. */
function parseAllowOsv(value: string | undefined): boolean | undefined {
  if (value === undefined) return undefined;
  return value.trim().toLowerCase() !== "false";
}

/** Reads KEYSNAG_FAIL_ON for the default `--fail-on` value. Falls back to "critical" if unset or invalid. */
export function loadFailOnDefault(): Severity | "off" {
  const raw = process.env.KEYSNAG_FAIL_ON;
  if (raw === "off" || (SEVERITIES as string[]).includes(raw ?? "")) {
    return raw as Severity | "off";
  }
  return "critical";
}

/** Filters the check registry to the given names, in registry order. Unknown names are dropped silently. */
export function loadEnabledChecks(names?: string[]): Check[] {
  if (!names || names.length === 0) return registry;
  const wanted = new Set(names);
  return registry.filter((c) => wanted.has(c.name));
}
