// deps: parses the repo's lockfile for exact installed versions, checks them against
// OSV.dev's batch API for known CVEs (the one allowed third-party call, opt-out via
// ctx.allowOsv=false), and adds offline hygiene rules: unpinned deps, install scripts
// in node_modules, and lockfile drift vs package.json.
import { readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import type { Check, CheckContext, CheckResult, Finding, Severity } from "../types.js";

const MAX_PACKAGES = 2000;
const OSV_BATCH_SIZE = 100;
const OSV_TIMEOUT_MS = 15_000;
const MAX_INSTALL_SCRIPT_DEPS = 500;

export interface PackageVersion {
  name: string;
  version: string;
}

/** Parse an npm package-lock.json (lockfileVersion 2 or 3, `packages` map). */
export function parsePackageLock(raw: string): PackageVersion[] {
  let data: any;
  try {
    data = JSON.parse(raw);
  } catch {
    return [];
  }
  const out: PackageVersion[] = [];
  const packages = data?.packages;
  if (packages && typeof packages === "object") {
    for (const [key, value] of Object.entries<any>(packages)) {
      if (key === "") continue; // root package
      const match = /(?:^|\/)node_modules\/((?:@[^/]+\/)?[^/]+)$/.exec(key);
      if (!match) continue;
      const version = value?.version;
      if (typeof version !== "string") continue;
      out.push({ name: match[1], version });
    }
    return out;
  }
  // lockfileVersion 1 fallback: top-level `dependencies` map
  const deps = data?.dependencies;
  if (deps && typeof deps === "object") {
    for (const [name, value] of Object.entries<any>(deps)) {
      const version = value?.version;
      if (typeof version === "string") out.push({ name, version });
    }
  }
  return out;
}

/** Parse a pnpm-lock.yaml `packages:` section without a YAML library (regex over keys). */
export function parsePnpmLock(raw: string): PackageVersion[] {
  const out: PackageVersion[] = [];
  const lines = raw.split("\n");
  let inPackages = false;
  let baseIndent: number | null = null;
  for (const line of lines) {
    if (/^packages:\s*$/.test(line)) {
      inPackages = true;
      baseIndent = null;
      continue;
    }
    if (!inPackages) continue;
    if (/^\S/.test(line)) {
      // dedented to a new top-level key: packages section ended
      if (!/^packages:/.test(line)) inPackages = false;
      continue;
    }
    const indentMatch = /^(\s+)(\S.*):\s*$/.exec(line);
    if (!indentMatch) continue;
    const indent = indentMatch[1].length;
    if (baseIndent === null) baseIndent = indent;
    if (indent !== baseIndent) continue; // nested key under a package entry, skip
    let key = indentMatch[2].trim();
    // strip surrounding quotes
    key = key.replace(/^['"]|['"]$/g, "");
    // keys look like "/name@version" or "name@version" or "/@scope/name@version"
    const stripped = key.startsWith("/") ? key.slice(1) : key;
    const at = stripped.lastIndexOf("@");
    if (at <= 0) continue;
    const name = stripped.slice(0, at);
    // version may carry a "(peerDep)" style suffix or "_peerHash"; keep the leading semver-ish token
    const rest = stripped.slice(at + 1);
    const versionMatch = /^[^\s(]+/.exec(rest);
    if (!versionMatch) continue;
    const version = versionMatch[0].split("_")[0];
    out.push({ name, version });
  }
  return out;
}

/** Parse a classic yarn.lock ("name@range:\n  version \"x\"" blocks). */
export function parseYarnLock(raw: string): PackageVersion[] {
  const out: PackageVersion[] = [];
  const blocks = raw.split(/\n\n+/);
  for (const block of blocks) {
    const lines = block.split("\n");
    const headerLine = lines.find((l) => /^[^\s#].*:\s*$/.test(l));
    if (!headerLine) continue;
    const versionLine = lines.find((l) => /^\s+version\s+"/.test(l));
    if (!versionLine) continue;
    const versionMatch = /version\s+"([^"]+)"/.exec(versionLine);
    if (!versionMatch) continue;
    const version = versionMatch[1];
    // header can list multiple comma-separated specs: "name@^1.0.0, name@~1.0.0:"
    const specs = headerLine.replace(/:\s*$/, "").split(",").map((s) => s.trim());
    const firstSpec = specs[0];
    // name is everything before the last "@" (scoped names contain a leading "@")
    const stripped = firstSpec.replace(/^"|"$/g, "");
    const at = stripped.lastIndexOf("@");
    if (at <= 0) continue;
    const name = stripped.slice(0, at).replace(/^"/, "");
    out.push({ name, version });
  }
  return out;
}

async function loadLockfile(repoDir: string, log: (msg: string) => void): Promise<{ packages: PackageVersion[]; found: boolean }> {
  const candidates: Array<{ file: string; parse: (raw: string) => PackageVersion[] }> = [
    { file: "package-lock.json", parse: parsePackageLock },
    { file: "pnpm-lock.yaml", parse: parsePnpmLock },
    { file: "yarn.lock", parse: parseYarnLock },
  ];
  for (const { file, parse } of candidates) {
    try {
      const raw = await readFile(join(repoDir, file), "utf8");
      const packages = parse(raw);
      log(`deps: parsed ${packages.length} package(s) from ${file}`);
      return { packages, found: true };
    } catch {
      continue;
    }
  }
  return { packages: [], found: false };
}

function dedupe(packages: PackageVersion[]): PackageVersion[] {
  const seen = new Map<string, PackageVersion>();
  for (const p of packages) {
    seen.set(`${p.name}@${p.version}`, p);
  }
  return [...seen.values()];
}

/** Parse a CVSS score from either a bare number string or a CVSS vector string. */
export function parseCvssScore(score: string): number | null {
  const num = Number(score);
  if (!Number.isNaN(num)) return num;
  // CVSS vector strings (e.g. "CVSS:3.1/AV:N/AC:L/...") don't carry the base score
  // directly; without a full calculator we cannot derive it reliably, so decline.
  return null;
}

/** Map an OSV vuln entry's severity info to keysnag's Severity, given fix availability. */
export function severityFromOsvVuln(vuln: any, hasFix: boolean): Severity {
  let score: number | null = null;

  const severities = Array.isArray(vuln?.severity) ? vuln.severity : [];
  for (const s of severities) {
    if (typeof s?.score === "string") {
      const parsed = parseCvssScore(s.score);
      if (parsed !== null) {
        score = score === null ? parsed : Math.max(score, parsed);
      }
    }
  }

  let sev: Severity;
  if (score !== null) {
    if (score >= 9) sev = "critical";
    else if (score >= 7) sev = "high";
    else if (score >= 4) sev = "medium";
    else sev = "low";
  } else {
    const dbSev = String(vuln?.database_specific?.severity ?? "").toUpperCase();
    if (dbSev === "CRITICAL") sev = "critical";
    else if (dbSev === "HIGH") sev = "high";
    else if (dbSev === "MODERATE") sev = "medium";
    else if (dbSev === "LOW") sev = "low";
    else sev = "medium"; // unknown severity: default to medium rather than silently dropping
  }

  if (sev === "critical" && !hasFix) sev = "high";
  return sev;
}

/** Whether an OSV vuln's affected ranges include a fixed event (a fix is available). */
function hasFixedVersion(vuln: any): boolean {
  const affected = Array.isArray(vuln?.affected) ? vuln.affected : [];
  for (const a of affected) {
    const ranges = Array.isArray(a?.ranges) ? a.ranges : [];
    for (const r of ranges) {
      const events = Array.isArray(r?.events) ? r.events : [];
      if (events.some((e: any) => typeof e?.fixed === "string")) return true;
    }
  }
  return false;
}

/** First fixed version string found in a vuln's affected ranges, if any. */
function firstFixedVersion(vuln: any): string | null {
  const affected = Array.isArray(vuln?.affected) ? vuln.affected : [];
  for (const a of affected) {
    const ranges = Array.isArray(a?.ranges) ? a.ranges : [];
    for (const r of ranges) {
      const events = Array.isArray(r?.events) ? r.events : [];
      for (const e of events) {
        if (typeof e?.fixed === "string") return e.fixed;
      }
    }
  }
  return null;
}

async function queryOsv(
  packages: PackageVersion[],
  log: (msg: string) => void,
): Promise<Finding[] | null> {
  const findings: Finding[] = [];
  for (let i = 0; i < packages.length; i += OSV_BATCH_SIZE) {
    const batch = packages.slice(i, i + OSV_BATCH_SIZE);
    const body = {
      queries: batch.map((p) => ({
        package: { name: p.name, ecosystem: "npm" },
        version: p.version,
      })),
    };
    let json: any;
    try {
      const res = await fetch("https://api.osv.dev/v1/querybatch", {
        method: "POST",
        headers: { "Content-Type": "application/json", "User-Agent": "keysnag-scan" },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(OSV_TIMEOUT_MS),
      });
      if (!res.ok) throw new Error(`OSV responded ${res.status}`);
      json = await res.json();
    } catch (err) {
      log(`deps: OSV query failed: ${(err as Error).message}`);
      return null;
    }

    const results = Array.isArray(json?.results) ? json.results : [];
    for (let j = 0; j < results.length; j++) {
      const pkg = batch[j];
      const vulns = Array.isArray(results[j]?.vulns) ? results[j].vulns : [];
      for (const v of vulns) {
        const id = v?.id ?? "unknown";
        const hasFix = hasFixedVersion(v);
        const severity = severityFromOsvVuln(v, hasFix);
        const fixedVersion = firstFixedVersion(v);
        const summary = v?.summary ?? v?.details ?? "No summary provided by OSV.";
        findings.push({
          id: "deps.known_cve",
          check: "deps",
          severity,
          title: `${pkg.name}@${pkg.version} has a known vulnerability (${id})`,
          detail: `${id}: ${summary} Installed version: ${pkg.version}.`,
          location: `package: ${pkg.name}`,
          fix: fixedVersion
            ? `Upgrade ${pkg.name} to ${fixedVersion} or later.`
            : `No fixed version is published yet for ${id}. Track the advisory and consider removing or replacing ${pkg.name} if the vulnerability is exploitable in this app's context.`,
        });
      }
    }
  }
  return findings;
}

interface PackageJsonShape {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

function unpinnedFindings(pkgJson: PackageJsonShape, lockfileFound: boolean): Finding[] {
  const findings: Finding[] = [];
  const allDeps: Array<[string, string, string]> = [];
  for (const [name, range] of Object.entries(pkgJson.dependencies ?? {})) allDeps.push([name, range, "dependencies"]);
  for (const [name, range] of Object.entries(pkgJson.devDependencies ?? {})) allDeps.push([name, range, "devDependencies"]);

  for (const [name, range, section] of allDeps) {
    if (range === "latest" || range === "*" || range === "") {
      findings.push({
        id: "deps.unpinned",
        check: "deps",
        severity: "medium",
        title: `${name} is not pinned to a version`,
        detail: `${section}.${name} is declared as "${range || "(empty)"}", which resolves to whatever is newest at install time. A future publish, including a compromised one, installs automatically.`,
        location: "package.json",
        fix: `Pin ${name} to an exact or range-bounded version in package.json, and commit a lockfile.`,
      });
    }
  }

  if (!lockfileFound && allDeps.length > 0) {
    findings.push({
      id: "deps.unpinned",
      check: "deps",
      severity: "medium",
      title: "No lockfile found",
      detail: "There is no package-lock.json, pnpm-lock.yaml, or yarn.lock in the repo. Without a lockfile, every install can resolve different transitive versions.",
      location: "package.json",
      fix: "Run your package manager's install command and commit the generated lockfile.",
    });
  }

  return findings;
}

async function installScriptFindings(repoDir: string, pkgJson: PackageJsonShape): Promise<Finding[]> {
  const findings: Finding[] = [];
  const names = [
    ...Object.keys(pkgJson.dependencies ?? {}),
    ...Object.keys(pkgJson.devDependencies ?? {}),
  ].slice(0, MAX_INSTALL_SCRIPT_DEPS);

  for (const name of names) {
    let manifest: any;
    try {
      const raw = await readFile(join(repoDir, "node_modules", name, "package.json"), "utf8");
      manifest = JSON.parse(raw);
    } catch {
      continue;
    }
    const scripts = manifest?.scripts ?? {};
    const hits = ["preinstall", "postinstall", "install"].filter((s) => typeof scripts[s] === "string");
    if (hits.length === 0) continue;
    findings.push({
      id: "deps.install_script",
      check: "deps",
      severity: "medium",
      title: `${name} runs a lifecycle install script`,
      detail: `${name} defines ${hits.join(", ")} script(s), which run arbitrary code during install. This is a common supply-chain attack vector (npm worm-class incidents).`,
      location: `node_modules/${name}/package.json`,
      fix: `Review ${name}'s ${hits.join("/")} script. If it is not needed, use an install-scripts allowlist (e.g. pnpm's or npm's ignore-scripts) to block it.`,
    });
  }

  return findings;
}

function lockfileStaleFindings(pkgJson: PackageJsonShape, lockedPackages: PackageVersion[]): Finding[] {
  const findings: Finding[] = [];
  const lockedNames = new Set(lockedPackages.map((p) => p.name));
  const allDeps = { ...(pkgJson.dependencies ?? {}), ...(pkgJson.devDependencies ?? {}) };
  for (const name of Object.keys(allDeps)) {
    if (!lockedNames.has(name)) {
      findings.push({
        id: "deps.lockfile_stale",
        check: "deps",
        severity: "low",
        title: `${name} is missing from the lockfile`,
        detail: `package.json declares ${name} but it does not appear in the lockfile. The lockfile is out of sync with package.json.`,
        location: "package.json",
        fix: `Run your package manager's install command to regenerate the lockfile so it matches package.json.`,
      });
    }
  }
  return findings;
}

async function pathExists(p: string): Promise<boolean> {
  try {
    await stat(p);
    return true;
  } catch {
    return false;
  }
}

const depsCheck: Check = {
  name: "deps",
  description: "Checks lockfile-pinned dependency versions against OSV.dev for known CVEs, plus offline hygiene: unpinned deps, install scripts, and lockfile drift.",
  requires: [],
  async run(ctx: CheckContext): Promise<CheckResult> {
    const repoDir = ctx.repoDir ?? ".";
    const findings: Finding[] = [];

    let pkgJson: PackageJsonShape = {};
    try {
      const raw = await readFile(join(repoDir, "package.json"), "utf8");
      pkgJson = JSON.parse(raw);
    } catch {
      return {
        check: "deps",
        ran: false,
        skippedReason: "no package.json found in repoDir",
        findings: [],
      };
    }

    const { packages, found: lockfileFound } = await loadLockfile(repoDir, ctx.log);
    const capped = dedupe(packages).slice(0, MAX_PACKAGES);

    findings.push(...unpinnedFindings(pkgJson, lockfileFound));
    if (lockfileFound) {
      findings.push(...lockfileStaleFindings(pkgJson, capped));
    }

    const nodeModulesExists = await pathExists(join(repoDir, "node_modules"));
    if (nodeModulesExists) {
      findings.push(...(await installScriptFindings(repoDir, pkgJson)));
    }

    if (ctx.allowOsv === false) {
      ctx.log("deps: OSV lookup skipped (allowOsv=false)");
    } else if (capped.length > 0) {
      const osvFindings = await queryOsv(capped, ctx.log);
      if (osvFindings === null) {
        findings.push({
          id: "deps.osv_unavailable",
          check: "deps",
          severity: "info",
          title: "OSV.dev CVE lookup unavailable",
          detail: "The OSV.dev batch API could not be reached, so known-CVE checking was skipped for this run. Offline dependency hygiene checks still ran.",
          fix: "Re-run keysnag with network access to check for known CVEs, or ignore if you intentionally run offline.",
        });
      } else {
        findings.push(...osvFindings);
      }
    }

    return { check: "deps", ran: true, findings };
  },
};

export default depsCheck;
