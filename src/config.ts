// Loads a CheckContext from CLI overrides, env vars, vibeguard.config.json, and a local .env.
// Precedence, highest first: CLI flags (passed in as `overrides`) > env vars > vibeguard.config.json.
import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import type { CheckContext, Check } from "./types.js";
import { checks as registry } from "./checks/index.js";

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

interface VibeguardConfigFile {
  repoDir?: string;
  siteUrl?: string;
  supabaseUrl?: string;
  supabaseAnonKey?: string;
  pgUrl?: string;
  tokenA?: string;
  tokenB?: string;
  checks?: string[];
}

function loadConfigFile(cwd: string): VibeguardConfigFile {
  const path = resolve(cwd, "vibeguard.config.json");
  if (!existsSync(path)) return {};
  try {
    return JSON.parse(readFileSync(path, "utf8")) as VibeguardConfigFile;
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
  log?: (msg: string) => void;
  cwd?: string;
}

/**
 * Builds a CheckContext. Precedence per field, highest first:
 * 1. `overrides` (CLI flags)
 * 2. env vars (VG_REPO_DIR, VG_SITE_URL, VG_SUPABASE_URL, VG_SUPABASE_ANON_KEY, VG_PG_URL, VG_TOKEN_A, VG_TOKEN_B)
 * 3. vibeguard.config.json in cwd
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
      overrides.repoDir ?? envOrDotEnv("VG_REPO_DIR") ?? config.repoDir,
    siteUrl:
      overrides.siteUrl ?? envOrDotEnv("VG_SITE_URL") ?? config.siteUrl,
    supabaseUrl:
      overrides.supabaseUrl ??
      envOrDotEnv("VG_SUPABASE_URL") ??
      config.supabaseUrl,
    supabaseAnonKey:
      overrides.supabaseAnonKey ??
      envOrDotEnv("VG_SUPABASE_ANON_KEY") ??
      config.supabaseAnonKey,
    pgUrl: overrides.pgUrl ?? envOrDotEnv("VG_PG_URL") ?? config.pgUrl,
    tokenA: overrides.tokenA ?? envOrDotEnv("VG_TOKEN_A") ?? config.tokenA,
    tokenB: overrides.tokenB ?? envOrDotEnv("VG_TOKEN_B") ?? config.tokenB,
    log: overrides.log ?? ((msg: string) => console.error(msg)),
  };
}

/** Filters the check registry to the given names, in registry order. Unknown names are dropped silently. */
export function loadEnabledChecks(names?: string[]): Check[] {
  if (!names || names.length === 0) return registry;
  const wanted = new Set(names);
  return registry.filter((c) => wanted.has(c.name));
}
