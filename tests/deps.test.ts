// tests/deps.test.ts — runs the real `deps` check against the seeded fixture with
// allowOsv=false (no network in tests), plus unit tests for the CVSS->severity mapping
// and the three lockfile parsers using inline strings.
import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import depsCheck, {
  parsePackageLock,
  parsePnpmLock,
  parseYarnLock,
  parseCvssScore,
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

test("parseCvssScore: a CVSS vector string cannot be scored without a calculator", () => {
  assert.equal(parseCvssScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), null);
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

test("skips cleanly when repoDir has no package.json", async () => {
  const result = await depsCheck.run(makeCtx({ repoDir: "/nonexistent-keysnag-fixture-dir" }));
  assert.equal(result.ran, false);
  assert.ok(result.skippedReason);
});
