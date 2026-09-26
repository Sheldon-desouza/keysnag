// tests/storage.test.ts — static half (edge_fn_no_jwt, cron_no_secret) against the
// seeded fixture, plus proof the pg half skips cleanly with no pgUrl. No network, no DB.
import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import storageCheck from "../src/checks/storage.js";
import type { CheckContext, Finding } from "../src/types.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixtureDir = resolve(__dirname, "..", "fixture", "storage");

function makeCtx(overrides: Partial<CheckContext> = {}): CheckContext {
  return { repoDir: fixtureDir, log: () => {}, ...overrides };
}

async function runStorage(overrides: Partial<CheckContext> = {}): Promise<Finding[]> {
  const result = await storageCheck.run(makeCtx(overrides));
  assert.equal(result.ran, true);
  return result.findings;
}

test("requires is empty so the check always runs, even with no pgUrl", () => {
  assert.deepEqual(storageCheck.requires, []);
});

test("finds an edge function deployed with verify_jwt = false", async () => {
  const findings = await runStorage();
  const hit = findings.find((f) => f.id === "storage.edge_fn_no_jwt");
  assert.ok(hit, "expected storage.edge_fn_no_jwt");
  assert.equal(hit?.severity, "high");
});

test("finds a cron route with no shared-secret check", async () => {
  const findings = await runStorage();
  const hit = findings.find((f) => f.id === "storage.cron_no_secret" && f.location?.includes("cron/sync"));
  assert.ok(hit, "expected storage.cron_no_secret on the cron/sync route");
});

test("does not flag the cron route that does check a shared secret", async () => {
  const findings = await runStorage();
  const hit = findings.find((f) => f.id === "storage.cron_no_secret" && f.location?.includes("cron/safe"));
  assert.equal(hit, undefined, "the safe cron route must not be flagged");
});

test("without pgUrl, the pg half is skipped cleanly (no connect_failed, no crash) and the static half still runs", async () => {
  const findings = await runStorage();
  assert.equal(findings.some((f) => f.id === "storage.connect_failed"), false);
  assert.ok(findings.length > 0, "static half should still have produced findings");
});

test("with an unreachable pgUrl, emits exactly one info storage.connect_failed and still runs the static half", async () => {
  const findings = await runStorage({ pgUrl: "postgres://user:pass@127.0.0.1:1/nonexistent" });
  const connectFailures = findings.filter((f) => f.id === "storage.connect_failed");
  assert.equal(connectFailures.length, 1);
  assert.equal(connectFailures[0].severity, "info");
  assert.ok(findings.some((f) => f.id === "storage.edge_fn_no_jwt"), "static half should still run");
});

test("an empty directory is clean", async () => {
  const dir = await mkdtemp(join(tmpdir(), "keysnag-storage-empty-"));
  const result = await storageCheck.run({ repoDir: dir, log: () => {} });
  assert.equal(result.ran, true);
  assert.equal(result.findings.length, 0);
});
