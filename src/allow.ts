// allow.ts — the exceptions baseline, modelled on a strict exceptions-baseline pattern:
// every suppressed finding must name why it's acceptable AND the control that bounds abuse.
// An entry missing either is not a valid exception; the gate refuses to run rather than let
// it through silently (see validateAllowList).
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import type { CheckResult, Finding } from "./types.js";

export interface AllowEntry {
  /** finding id, or a prefix of it (e.g. "secret." matches "secret.stripe_key") */
  id: string;
  /** file, "file:line", or a glob (supports "*" and "**") matched against finding.location */
  location: string;
  /** why this is acceptable, required, non-empty */
  reason: string;
  /** the compensating control that stops abuse, required, non-empty, e.g. "auth + 20/hr rate limit" */
  bound: string;
}

/** Reads and validates the `allow` array out of a parsed keysnag.config.json body. Throws a clear,
 * itemised error (naming every bad entry) if any entry lacks a non-empty `reason` or `bound`. */
export function loadAllowList(configPath: string): AllowEntry[] {
  if (!existsSync(configPath)) return [];
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(configPath, "utf8"));
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new Error(`keysnag: ${configPath} is not valid JSON (${message})`);
  }
  const allow = (raw as { allow?: unknown }).allow;
  if (allow === undefined) return [];
  if (!Array.isArray(allow)) {
    throw new Error(`keysnag: "allow" in ${configPath} must be an array of entries`);
  }
  return validateAllowList(allow as unknown[], configPath);
}

// A valid id is either a concrete finding id ("<check>.<rule>", e.g. "secret.stripe_key")
// or a dotted prefix of one with at least one segment after the check name ("secret."),
// each segment lowercase-alnum-with-hyphens/underscores. A bare check name with no trailing
// dot ("secret") is not specific enough and is rejected below.
function isConcreteId(id: string): boolean {
  // has at least one "." followed by a rule-name segment, e.g. "secret.stripe_key"
  return /^[a-z][a-z0-9-]*\.[a-z0-9_]+$/.test(id);
}

function isDottedPrefix(id: string): boolean {
  // e.g. "secret." or "authz.route_" — a check name (plus optional segments) with a trailing dot
  return /^[a-z][a-z0-9-]*(\.[a-z0-9_]+)*\.$/.test(id);
}

function isWideOpenLocation(location: string): boolean {
  // "**/*", "**/**", "*/**", "./**" are catch-alls too. A location is
  // wide open when it contains no literal path segment at all.
  return /^[\s*./\\]*$/.test(location);
}

/** Validates a raw allow array. Throws naming every entry that is missing a non-empty reason
 * and/or bound, has an empty or malformed id, or pairs a wide-open location ("**"/"*"/missing)
 * with anything less specific than a full concrete finding id — an unannotated or unbounded
 * exception is refused outright. */
export function validateAllowList(entries: unknown[], sourceLabel = "keysnag.config.json"): AllowEntry[] {
  const bad: string[] = [];
  const result: AllowEntry[] = [];

  entries.forEach((raw, i) => {
    const entry = raw as Partial<AllowEntry>;
    const id = typeof entry.id === "string" ? entry.id.trim() : "";
    const location = typeof entry.location === "string" ? entry.location.trim() : "";
    const reason = typeof entry.reason === "string" ? entry.reason.trim() : "";
    const bound = typeof entry.bound === "string" ? entry.bound.trim() : "";

    const missing: string[] = [];
    if (!reason) missing.push("reason");
    if (!bound) missing.push("bound");

    const label = `entry ${i} (id: "${id || "?"}", location: "${location || "?"}")`;

    if (missing.length > 0) {
      bad.push(`  - ${label} is missing ${missing.join(" and ")}`);
      return;
    }

    if (!id) {
      bad.push(`  - ${label} has an empty id — name a specific finding id (e.g. "secret.stripe_key") or a dotted prefix (e.g. "secret.")`);
      return;
    }

    const concrete = isConcreteId(id);
    const prefix = isDottedPrefix(id);
    if (!concrete && !prefix) {
      bad.push(`  - ${label} has a malformed id — must be a concrete finding id or a dotted prefix like "<check>." (e.g. "secret.stripe_key" or "secret.")`);
      return;
    }

    if (isWideOpenLocation(location) && !concrete) {
      bad.push(`  - ${label} pairs a wide-open location ("${location || "(missing)"}") with a prefix-only id — name a specific finding id or a narrower location`);
      return;
    }

    result.push({ id, location, reason, bound });
  });

  if (bad.length > 0) {
    throw new Error(
      [
        `keysnag: refusing to run — these entries in ${sourceLabel} "allow" are invalid:`,
        ...bad,
        "",
        'Every exception must name a specific finding id (or a dotted prefix like "secret.") and, if the',
        "location is wide open (\"**\"/\"*\"/missing), the id must be a full concrete finding id. It must also",
        'state "reason" (why it is acceptable) and "bound" (the control that stops abuse, e.g. a rate',
        'limit, a quota, an auth check, or "no user data"). If there is no such bound, add one to the code',
        "instead of listing it here.",
      ].join("\n"),
    );
  }

  return result;
}

/** Converts a location glob ("*" and "**") into a RegExp. No dependency; small and deliberate. */
function globToRegExp(glob: string): RegExp {
  let out = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === "*" && glob[i + 1] === "*") {
      out += ".*";
      i++;
    } else if (c === "*") {
      out += "[^/]*";
    } else if (".+?^${}()|[]\\".includes(c)) {
      out += `\\${c}`;
    } else {
      out += c;
    }
  }
  return new RegExp(`^${out}$`);
}

function isGlob(pattern: string): boolean {
  return pattern.includes("*");
}

/** file part of a "file:line" (or "file") location string. */
function fileOf(location: string): string {
  const idx = location.lastIndexOf(":");
  // don't split a windows drive letter or a bare colon-free path; only split if what follows looks like a line number
  if (idx === -1) return location;
  const rest = location.slice(idx + 1);
  return /^\d+$/.test(rest) ? location.slice(0, idx) : location;
}

function locationMatches(entryLocation: string, findingLocation: string | undefined): boolean {
  if (!findingLocation) return false;
  if (entryLocation === findingLocation) return true;
  if (entryLocation === fileOf(findingLocation)) return true;
  if (isGlob(entryLocation)) {
    const re = globToRegExp(entryLocation);
    if (re.test(findingLocation)) return true;
    if (re.test(fileOf(findingLocation))) return true;
  }
  return false;
}

function idMatches(entryId: string, findingId: string): boolean {
  return findingId === entryId || findingId.startsWith(entryId);
}

/** Applies the allow list to results: any finding matching an entry is downgraded to "info", its title
 * prefixed "[allowed] ", and its detail appended with the reason and bound. Never removes a finding;
 * an allowed finding still shows up, it just never blocks (exitCodeForFindings ranks "info" lowest). */
export function applyAllowList(results: CheckResult[], entries: AllowEntry[]): CheckResult[] {
  if (entries.length === 0) return results;

  return results.map((result) => ({
    ...result,
    findings: result.findings.map((finding) => {
      const match = entries.find(
        (entry) => idMatches(entry.id, finding.id) && locationMatches(entry.location, finding.location),
      );
      if (!match) return finding;

      const allowed: Finding = {
        ...finding,
        severity: "info",
        title: finding.title.startsWith("[allowed] ") ? finding.title : `[allowed] ${finding.title}`,
        detail: `${finding.detail} Allowed: ${match.reason}. Bound: ${match.bound}.`,
      };
      return allowed;
    }),
  }));
}

/** Appends a new, valid allow entry to keysnag.config.json in `cwd`, creating the file if missing and
 * preserving any other keys already there. Throws if reason or bound is empty. */
export function appendAllowEntry(cwd: string, entry: AllowEntry): void {
  const reason = entry.reason.trim();
  const bound = entry.bound.trim();
  if (!reason || !bound) {
    throw new Error("keysnag: --reason and --bound are both required and must be non-empty");
  }

  const configPath = resolve(cwd, "keysnag.config.json");
  let config: Record<string, unknown> = {};
  if (existsSync(configPath)) {
    try {
      config = JSON.parse(readFileSync(configPath, "utf8")) as Record<string, unknown>;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      throw new Error(`keysnag: ${configPath} is not valid JSON (${message})`);
    }
  }

  const existing = Array.isArray(config.allow) ? (config.allow as AllowEntry[]) : [];
  const next: AllowEntry = { id: entry.id, location: entry.location, reason, bound };
  config.allow = [...existing, next];

  writeFileSync(configPath, `${JSON.stringify(config, null, 2)}\n`, "utf8");
}
