// tests/deps.test.ts — runs the real `deps` check against the seeded fixture with
// allowOsv=false (no network in tests), plus unit tests for the CVSS->severity mapping
// and the three lockfile parsers using inline strings.
import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import depsCheck, {
  createDepsCheck,
  parsePackageLock,
  parsePnpmLock,
  parseYarnLock,
  parseCvssScore,
  cvssBaseScoreFromVector,
  severityFromOsvVuln,
} from "../src/checks/deps.js";
import type { CheckContext } from "../src/types.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixtureDir = resolve(__dirname, "..", "fixture", "deps");

function makeCtx(overrides: Partial<CheckContext> = {}): CheckContext {
  return { repoDir: fixtureDir, allowOsv: false, log: () => {}, ...overrides };
}

test("deps check runs offline (allowOsv=false) with no network", async () => {
  const result = await depsCheck.run(makeCtx());
  assert.equal(result.ran, true);
  // no osv_unavailable finding when OSV was never attempted
  assert.ok(!result.findings.some((f) => f.id === "deps.osv_unavailable"));
});

test("finds the unpinned 'latest' dependency", async () => {
  const result = await depsCheck.run(makeCtx());
  const hit = result.findings.find((f) => f.id === "deps.unpinned" && f.title.includes("left-pad"));
  assert.ok(hit, "expected a deps.unpinned finding for left-pad");
  assert.equal(hit?.severity, "medium");
});

test("finds deps.install_script for a package with a postinstall script in node_modules", async () => {
  const result = await depsCheck.run(makeCtx());
  const hit = result.findings.find((f) => f.id === "deps.install_script" && f.title.includes("shady-pkg"));
  assert.ok(hit, "expected a deps.install_script finding for shady-pkg");
  assert.equal(hit?.severity, "medium");
  assert.match(hit!.location!, /node_modules\/shady-pkg\/package\.json/);
});

test("finds deps.lockfile_stale for a package.json dep missing from the lockfile", async () => {
  const result = await depsCheck.run(makeCtx());
  const hit = result.findings.find((f) => f.id === "deps.lockfile_stale" && f.title.includes("shady-pkg"));
  assert.ok(hit, "expected a deps.lockfile_stale finding for shady-pkg");
  assert.equal(hit?.severity, "low");
});

test("lockfile parsing: package-lock.json v3 packages map", async () => {
  const result = await depsCheck.run(makeCtx());
  // lodash is pinned and present in the lockfile, so no unpinned/stale finding for it
  assert.ok(!result.findings.some((f) => f.title.includes("lodash") && f.id === "deps.unpinned"));
});

test("parsePackageLock: reads node_modules/<name> versions, skips the root", () => {
  const raw = JSON.stringify({
    packages: {
      "": { name: "root", version: "1.0.0" },
      "node_modules/lodash": { version: "4.17.15" },
      "node_modules/@scope/pkg": { version: "2.0.0" },
    },
  });
  const packages = parsePackageLock(raw);
  assert.deepEqual(
    packages.sort((a, b) => a.name.localeCompare(b.name)),
    [
      { name: "@scope/pkg", version: "2.0.0" },
      { name: "lodash", version: "4.17.15" },
    ],
  );
});

test("parsePnpmLock: reads packages: keys", () => {
  const raw = [
    "lockfileVersion: '6.0'",
    "",
    "packages:",
    "",
    "  /lodash@4.17.15:",
    "    resolution: {integrity: sha512-xxx}",
    "",
    "  /@scope/pkg@2.0.0:",
    "    resolution: {integrity: sha512-yyy}",
    "",
    "settings:",
    "  foo: bar",
  ].join("\n");
  const packages = parsePnpmLock(raw);
  assert.deepEqual(
    packages.sort((a, b) => a.name.localeCompare(b.name)),
    [
      { name: "@scope/pkg", version: "2.0.0" },
      { name: "lodash", version: "4.17.15" },
    ],
  );
});

test("parseYarnLock: reads classic 'name@range:' blocks with version literal", () => {
  const raw = [
    'lodash@^4.17.0:',
    '  version "4.17.15"',
    '  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.15.tgz"',
    "",
    '"@scope/pkg@^2.0.0":',
    '  version "2.0.0"',
    '  resolved "https://registry.yarnpkg.com/@scope/pkg/-/pkg-2.0.0.tgz"',
  ].join("\n");
  const packages = parseYarnLock(raw);
  assert.deepEqual(
    packages.sort((a, b) => a.name.localeCompare(b.name)),
    [
      { name: "@scope/pkg", version: "2.0.0" },
      { name: "lodash", version: "4.17.15" },
    ],
  );
});

test("parseCvssScore: numeric string passes through", () => {
  assert.equal(parseCvssScore("9.8"), 9.8);
});

test("parseCvssScore: a CVSS vector string is now scored via the CVSS 3.x calculator", () => {
  assert.equal(parseCvssScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8);
});

test("severityFromOsvVuln: CVSS >= 9 with a fix is critical", () => {
  const vuln = { severity: [{ type: "CVSS_V3", score: "9.8" }] };
  assert.equal(severityFromOsvVuln(vuln, true), "critical");
});

test("severityFromOsvVuln: CVSS >= 9 without a fix is capped at high", () => {
  const vuln = { severity: [{ type: "CVSS_V3", score: "9.8" }] };
  assert.equal(severityFromOsvVuln(vuln, false), "high");
});

test("severityFromOsvVuln: CVSS 7-9 is high", () => {
  const vuln = { severity: [{ type: "CVSS_V3", score: "7.5" }] };
  assert.equal(severityFromOsvVuln(vuln, true), "high");
});

test("severityFromOsvVuln: CVSS 4-7 is medium", () => {
  const vuln = { severity: [{ type: "CVSS_V3", score: "5.0" }] };
  assert.equal(severityFromOsvVuln(vuln, true), "medium");
});

test("severityFromOsvVuln: CVSS < 4 is low", () => {
  const vuln = { severity: [{ type: "CVSS_V3", score: "2.0" }] };
  assert.equal(severityFromOsvVuln(vuln, true), "low");
});

test("severityFromOsvVuln: falls back to database_specific.severity when no CVSS score", () => {
  const vuln = { database_specific: { severity: "HIGH" } };
  assert.equal(severityFromOsvVuln(vuln, true), "high");
});

test("cvssBaseScoreFromVector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8", () => {
  assert.equal(cvssBaseScoreFromVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8);
});

test("cvssBaseScoreFromVector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N = 5.4", () => {
  assert.equal(cvssBaseScoreFromVector("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"), 5.4);
});

test("cvssBaseScoreFromVector: CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H = 7.2 per the spec formula", () => {
  // The chair's remembered value (7.5) does not match the FIRST.org worked formula (ISS/impact/
  // exploitability/scope/roundup) for this vector; 7.2 is what the spec's own arithmetic produces.
  assert.equal(cvssBaseScoreFromVector("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H"), 7.2);
});

test("parseCvssScore: routes a CVSS vector string through the calculator", () => {
  assert.equal(parseCvssScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8);
});

function fakeOsvFetch(
  querybatchResults: any[],
  vulnDetails: Record<string, any>,
): typeof fetch {
  return (async (input: any, init?: any) => {
    const url = String(input);
    if (url === "https://api.osv.dev/v1/querybatch") {
      return new Response(JSON.stringify({ results: querybatchResults }), { status: 200 });
    }
    const match = /\/v1\/vulns\/(.+)$/.exec(url);
    if (match) {
      const id = decodeURIComponent(match[1]);
      if (id in vulnDetails) {
        const detail = vulnDetails[id];
        if (detail === null) return new Response("boom", { status: 500 });
        return new Response(JSON.stringify(detail), { status: 200 });
      }
    }
    return new Response("not found", { status: 404 });
  }) as unknown as typeof fetch;
}

test("deps.known_cve: groups multiple advisories for lodash into one finding, picks the fixed version, sorts severity", async () => {
  // The fixture's package-lock.json pins only lodash; left-pad and shady-pkg are not in the
  // lockfile (that's what makes them fire deps.unpinned/deps.lockfile_stale instead), so the
  // OSV querybatch is only ever called with lodash.
  const fakeFetch = fakeOsvFetch(
    [{ vulns: [{ id: "GHSA-old" }, { id: "GHSA-new" }] }], // lodash
    {
      "GHSA-old": {
        id: "GHSA-old",
        summary: "Prototype pollution in zipObjectDeep",
        severity: [{ type: "CVSS_V3", score: "7.4" }],
        affected: [{ package: { name: "lodash" }, ranges: [{ events: [{ fixed: "4.17.19" }] }] }],
      },
      "GHSA-new": {
        id: "GHSA-new",
        summary: "Command injection via template",
        severity: [{ type: "CVSS_V3", score: "9.8" }],
        affected: [{ package: { name: "lodash" }, ranges: [{ events: [{ fixed: "4.17.21" }] }] }],
      },
    },
  );
  const check = createDepsCheck(fakeFetch);
  const result = await check.run(makeCtx({ allowOsv: true }));
  const hits = result.findings.filter((f) => f.id === "deps.known_cve");
  assert.equal(hits.length, 1, "expected exactly one grouped finding for lodash");
  const hit = hits[0];
  assert.equal(hit.severity, "critical"); // highest of the two (9.8, with a fix)
  assert.match(hit.title, /^lodash@4\.17\.15 has 2 known vulnerabilities \(highest: critical\)$/);
  assert.match(hit.detail, /GHSA-old/);
  assert.match(hit.detail, /GHSA-new/);
  assert.equal(hit.location, "package-lock.json:lodash@4.17.15");
  assert.equal(hit.fix, "Upgrade lodash to 4.17.21.");
});

test("deps.known_cve: a failed vuln-detail fetch degrades to medium with a 'severity unavailable' note", async () => {
  const fakeFetch = fakeOsvFetch(
    [{ vulns: [{ id: "GHSA-unreachable" }] }], // lodash
    { "GHSA-unreachable": null },
  );
  const check = createDepsCheck(fakeFetch);
  const result = await check.run(makeCtx({ allowOsv: true }));
  const hit = result.findings.find((f) => f.id === "deps.known_cve");
  assert.ok(hit);
  assert.equal(hit?.severity, "medium");
  assert.match(hit!.detail, /severity unavailable/);
});

test("skips cleanly when repoDir has no package.json", async () => {
  const result = await depsCheck.run(makeCtx({ repoDir: "/nonexistent-keysnag-fixture-dir" }));
  assert.equal(result.ran, false);
  assert.ok(result.skippedReason);
});
