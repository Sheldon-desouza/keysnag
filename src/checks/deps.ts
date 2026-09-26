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
const MAX_VULN_IDS = 300;
const VULN_FETCH_CONCURRENCY = 6;

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

async function loadLockfile(repoDir: string, log: (msg: string) => void): Promise<{ packages: PackageVersion[]; found: boolean; file: string }> {
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
      return { packages, found: true, file };
    } catch {
      continue;
    }
  }
  return { packages: [], found: false, file: "package-lock.json" };
}

function dedupe(packages: PackageVersion[]): PackageVersion[] {
  const seen = new Map<string, PackageVersion>();
  for (const p of packages) {
    seen.set(`${p.name}@${p.version}`, p);
  }
  return [...seen.values()];
}

// CVSS 3.x base-score calculator (FIRST.org spec section 7.1). Metric weights per the
// official tables; scope ("S") changes the PR weight and the impact formula.
const CVSS_AV: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const CVSS_AC: Record<string, number> = { L: 0.77, H: 0.44 };
const CVSS_UI: Record<string, number> = { N: 0.85, R: 0.62 };
const CVSS_PR_UNCHANGED: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 };
const CVSS_PR_CHANGED: Record<string, number> = { N: 0.85, L: 0.68, H: 0.5 };
const CVSS_CIA: Record<string, number> = { H: 0.56, L: 0.22, N: 0 };

/** CVSS's Roundup(x): round up to the nearest 0.1. */
function cvssRoundUp(x: number): number {
  const intInput = Math.round(x * 100000);
  if (intInput % 10000 === 0) return intInput / 100000;
  return (Math.floor(intInput / 10000) + 1) / 10;
}

/** Compute a CVSS 3.x base score from a vector string, e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H". */
export function cvssBaseScoreFromVector(vector: string): number | null {
  if (!/^CVSS:3\.[01]\//.test(vector)) return null;
  const metrics: Record<string, string> = {};
  for (const part of vector.split("/").slice(1)) {
    const [key, value] = part.split(":");
    if (key && value) metrics[key] = value;
  }
  const scope = metrics.S;
  if (scope !== "U" && scope !== "C") return null;

  const av = CVSS_AV[metrics.AV];
  const ac = CVSS_AC[metrics.AC];
  const ui = CVSS_UI[metrics.UI];
  const pr = (scope === "C" ? CVSS_PR_CHANGED : CVSS_PR_UNCHANGED)[metrics.PR];
  const c = CVSS_CIA[metrics.C];
  const i = CVSS_CIA[metrics.I];
  const a = CVSS_CIA[metrics.A];
  if ([av, ac, ui, pr, c, i, a].some((v) => v === undefined)) return null;

  const iss = 1 - (1 - c!) * (1 - i!) * (1 - a!);
  const impact = scope === "U" ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  const exploitability = 8.22 * av! * ac! * pr! * ui!;
  if (impact <= 0) return 0;
  const base = scope === "U" ? impact + exploitability : 1.08 * (impact + exploitability);
  return cvssRoundUp(Math.min(base, 10));
}

/** Parse a CVSS score from either a bare number string or a CVSS vector string. */
export function parseCvssScore(score: string): number | null {
  if (/^CVSS:3\./.test(score)) return cvssBaseScoreFromVector(score);
  const num = Number(score);
  if (!Number.isNaN(num)) return num;
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

/** Compare two dotted version strings numerically, ignoring any -prerelease/+build suffix. */
function compareVersions(a: string, b: string): number {
  const numsOf = (v: string) => v.split(/[-+]/)[0].split(".").map((n) => parseInt(n, 10) || 0);
  const pa = numsOf(a);
  const pb = numsOf(b);
  const len = Math.max(pa.length, pb.length);
  for (let idx = 0; idx < len; idx++) {
    const diff = (pa[idx] ?? 0) - (pb[idx] ?? 0);
    if (diff !== 0) return diff;
  }
  const aPre = /[-+]/.test(a);
  const bPre = /[-+]/.test(b);
  if (aPre !== bPre) return aPre ? -1 : 1; // a plain release outranks a prerelease at the same numeric version
  return 0;
}

/** All `fixed` events across a vuln's affected ranges for the named package (npm ecosystem). */
function fixedVersionsFor(vuln: any, packageName: string): string[] {
  const affected = Array.isArray(vuln?.affected) ? vuln.affected : [];
  const out: string[] = [];
  for (const a of affected) {
    const pkgName = a?.package?.name;
    if (pkgName && pkgName !== packageName) continue;
    const ranges = Array.isArray(a?.ranges) ? a.ranges : [];
    for (const r of ranges) {
      const events = Array.isArray(r?.events) ? r.events : [];
      for (const e of events) {
        if (typeof e?.fixed === "string") out.push(e.fixed);
      }
    }
  }
  return out;
}

/**
 * The fixed version for the specific vulnerable interval that contains `installed`, walking
 * each range's events (introduced/fixed/last_affected) in order per the OSV range spec. Returns
 * null if `installed` falls in an interval with no fix yet (last_affected, no fixed event), or
 * if no interval in this vuln's ranges actually contains it.
 */
function fixedVersionForInterval(vuln: any, packageName: string, installed: string): string | null {
  const affected = Array.isArray(vuln?.affected) ? vuln.affected : [];
  for (const a of affected) {
    const pkgName = a?.package?.name;
    if (pkgName && pkgName !== packageName) continue;
    const ranges = Array.isArray(a?.ranges) ? a.ranges : [];
    for (const r of ranges) {
      const events = Array.isArray(r?.events) ? r.events : [];
      let introduced: string | null = null;
      for (const e of events) {
        if (typeof e?.introduced === "string") {
          introduced = e.introduced;
        } else if (typeof e?.fixed === "string") {
          const lower = introduced ?? "0";
          if (compareVersions(installed, lower) >= 0 && compareVersions(installed, e.fixed) < 0) {
            return e.fixed;
          }
          introduced = null;
        } else if (typeof e?.last_affected === "string") {
          const lower = introduced ?? "0";
          if (compareVersions(installed, lower) >= 0 && compareVersions(installed, e.last_affected) <= 0) {
            return null; // affected by this interval, but no fix has been published for it
          }
          introduced = null;
        }
      }
    }
  }
  return null;
}

/** Smallest fixed version >= installed for the named package; falls back to the largest fixed version found if none clears installed. */
function pickFixedVersion(fixedVersions: string[], installed: string): string | null {
  if (fixedVersions.length === 0) return null;
  const atOrAbove = fixedVersions.filter((v) => compareVersions(v, installed) >= 0);
  const pool = atOrAbove.length > 0 ? atOrAbove : fixedVersions;
  return pool.reduce((best, v) => (compareVersions(v, best) < 0 ? v : best));
}

/** Fetch a single OSV vuln by id, User-Agent keysnag-scan, 15s timeout. Returns null on any failure. */
async function fetchVuln(id: string, fetchImpl: typeof fetch, log: (msg: string) => void): Promise<any | null> {
  try {
    const res = await fetchImpl(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`, {
      headers: { "User-Agent": "keysnag-scan" },
      signal: AbortSignal.timeout(OSV_TIMEOUT_MS),
    });
    if (!res.ok) throw new Error(`OSV vuln lookup responded ${res.status}`);
    return await res.json();
  } catch (err) {
    log(`deps: OSV vuln detail fetch failed for ${id}: ${(err as Error).message}`);
    return null;
  }
}

/** Fetch OSV vuln details for each id with bounded concurrency; failures resolve to null (graceful degradation). */
async function fetchVulnDetails(
  ids: string[],
  fetchImpl: typeof fetch,
  log: (msg: string) => void,
): Promise<Map<string, any | null>> {
  const details = new Map<string, any | null>();
  let next = 0;
  async function worker() {
    while (next < ids.length) {
      const id = ids[next++];
      details.set(id, await fetchVuln(id, fetchImpl, log));
    }
  }
  const workers = Array.from({ length: Math.min(VULN_FETCH_CONCURRENCY, ids.length) }, () => worker());
  await Promise.all(workers);
  return details;
}

const SEVERITY_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

/**
 * Query OSV.dev querybatch for each package's advisory ids, fetch full details for every
 * unique id (deduped, capped, bounded concurrency), then group into one deps.known_cve
 * finding per package.
 */
async function queryOsv(
  packages: PackageVersion[],
  lockfileName: string,
  fetchImpl: typeof fetch,
  log: (msg: string) => void,
): Promise<Finding[] | null> {
  // Phase 1: querybatch -> advisory ids per package.
  const idsByPackage = new Map<PackageVersion, string[]>();
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
      const res = await fetchImpl("https://api.osv.dev/v1/querybatch", {
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
      const ids = vulns.map((v: any) => v?.id).filter((id: any): id is string => typeof id === "string");
      if (ids.length > 0) idsByPackage.set(pkg, ids);
    }
  }

  if (idsByPackage.size === 0) return [];

  // Phase 2: fetch full details for every unique advisory id (dedupe, cap 300).
  const uniqueIds = [...new Set([...idsByPackage.values()].flat())].slice(0, MAX_VULN_IDS);
  const details = await fetchVulnDetails(uniqueIds, fetchImpl, log);

  // Phase 3: group into one finding per package.
  const findings: Finding[] = [];
  for (const [pkg, ids] of idsByPackage) {
    let worstSeverity: Severity = "low";
    const lines: string[] = [];
    // The version that resolves EVERY advisory for this package is the largest of each
    // advisory's own minimal fix (smallest fixed >= installed); the smallest overall fix
    // would still leave a later advisory unpatched.
    const perAdvisoryFixed: string[] = [];

    for (const id of ids) {
      const vuln = details.get(id);
      let severity: Severity;
      let summaryLine: string;
      if (vuln == null) {
        severity = "medium";
        summaryLine = `${id}: severity unavailable (OSV detail lookup failed)`;
      } else {
        const fixedForPkg = fixedVersionsFor(vuln, pkg.name);
        const hasFix = fixedForPkg.length > 0;
        severity = severityFromOsvVuln(vuln, hasFix);
        const summary = vuln?.summary ?? vuln?.details ?? "No summary provided by OSV.";
        // Prefer the fix for the specific vulnerable interval installed falls in; fall back to
        // the naive smallest-fixed->=-installed pick if the range data doesn't resolve cleanly.
        const fixedForThis = fixedVersionForInterval(vuln, pkg.name, pkg.version) ?? pickFixedVersion(fixedForPkg, pkg.version);
        if (fixedForThis) perAdvisoryFixed.push(fixedForThis);
        summaryLine = `${id}: ${summary}${fixedForThis ? ` (fixed: ${fixedForThis})` : " (no fixed version published)"}`;
      }
      lines.push(summaryLine);
      if (SEVERITY_RANK[severity] > SEVERITY_RANK[worstSeverity]) worstSeverity = severity;
    }

    const packageFixed =
      perAdvisoryFixed.length > 0
        ? perAdvisoryFixed.reduce((max, v) => (compareVersions(v, max) > 0 ? v : max))
        : null;
    findings.push({
      id: "deps.known_cve",
      check: "deps",
      severity: worstSeverity,
      title: `${pkg.name}@${pkg.version} has ${ids.length} known vulnerabilities (highest: ${worstSeverity})`,
      detail: lines.join("\n"),
      location: `${lockfileName}:${pkg.name}@${pkg.version}`,
      fix: packageFixed
        ? perAdvisoryFixed.length === ids.length
          ? `Upgrade ${pkg.name} to ${packageFixed}.`
          : `Upgrade ${pkg.name} to ${packageFixed} (fixes ${perAdvisoryFixed.length} of ${ids.length} advisories; ${ids.length - perAdvisoryFixed.length} have no published fix yet, so track them and consider replacing ${pkg.name} if they are exploitable in this app's context).`
        : `No fixed version has been published for ${pkg.name}'s known advisories. Track them and consider removing or replacing ${pkg.name} if exploitable in this app's context.`,
    });
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

/**
 * Build the `deps` Check. `fetchImpl` defaults to the global `fetch` but is injectable
 * so tests can supply fake OSV responses (querybatch + per-vuln lookups) with no network.
 */
export function createDepsCheck(fetchImpl: typeof fetch = fetch): Check {
  return {
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

      const { packages, found: lockfileFound, file: lockfileName } = await loadLockfile(repoDir, ctx.log);
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
        const osvFindings = await queryOsv(capped, lockfileName, fetchImpl, ctx.log);
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
}

const depsCheck: Check = createDepsCheck();

export default depsCheck;
