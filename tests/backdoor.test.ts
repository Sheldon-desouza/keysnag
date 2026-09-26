// tests/backdoor.test.ts — runs the real `backdoor` check against the seeded fixture
// (no network, no DB) and asserts each seeded flaw fires only its own id.
import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import backdoorCheck from "../src/checks/backdoor.js";
import type { CheckContext, Finding } from "../src/types.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixtureDir = resolve(__dirname, "..", "fixture", "backdoor");

function makeCtx(): CheckContext {
  return { repoDir: fixtureDir, log: () => {} };
}

async function runBackdoor(): Promise<Finding[]> {
  const result = await backdoorCheck.run(makeCtx());
  assert.equal(result.ran, true);
  return result.findings;
}

test("requires is empty", () => {
  assert.deepEqual(backdoorCheck.requires, []);
});

test("finds the obfuscated base64-eval chain", async () => {
  const findings = await runBackdoor();
  const hit = findings.find((f) => f.id === "backdoor.obfuscated_eval" && f.location?.includes("obfuscated_eval.ts"));
  assert.ok(hit);
  assert.equal(hit?.severity, "critical");
});

test("finds a hardcoded password literal bypass as critical", async () => {
  const findings = await runBackdoor();
  const hit = findings.find(
    (f) => f.id === "backdoor.literal_bypass" && f.location?.includes("literal_bypass.ts") && f.title.includes("password"),
  );
  assert.ok(hit);
  assert.equal(hit?.severity, "critical");
});

test("finds a hardcoded role literal bypass as high", async () => {
  const findings = await runBackdoor();
  const hit = findings.find(
    (f) => f.id === "backdoor.literal_bypass" && f.location?.includes("literal_bypass.ts") && f.title.includes("role"),
  );
  assert.ok(hit);
  assert.equal(hit?.severity, "high");
});

test("finds the auth-skip flag", async () => {
  const findings = await runBackdoor();
  const hit = findings.find((f) => f.id === "backdoor.auth_skip_flag" && f.location?.includes("auth_skip_flag.ts"));
  assert.ok(hit);
  assert.equal(hit?.severity, "high");
});

test("finds process.env dumped into a response", async () => {
  const findings = await runBackdoor();
  const hit = findings.find((f) => f.id === "backdoor.env_dump" && f.location?.includes("env_dump.ts"));
  assert.ok(hit);
  assert.equal(hit?.severity, "high");
});

test("finds an unexpected outbound host, but not an allowlisted one", async () => {
  const findings = await runBackdoor();
  const hit = findings.find((f) => f.id === "backdoor.unexpected_outbound" && f.location?.includes("unexpected_outbound.ts"));
  assert.ok(hit);
  assert.equal(hit?.severity, "medium");
  const falsePositive = findings.find((f) => f.id === "backdoor.unexpected_outbound" && f.location?.includes("safe.ts"));
  assert.equal(falsePositive, undefined, "an allowlisted host (stripe.com) must not be flagged");
});

test("finds the prompt-injection artifact", async () => {
  const findings = await runBackdoor();
  const hit = findings.find((f) => f.id === "backdoor.prompt_injection_artifact" && f.location?.includes("prompt_injection_artifact.ts"));
  assert.ok(hit);
  assert.equal(hit?.severity, "medium");
});

test("the safe fixture is clean", async () => {
  const findings = await runBackdoor();
  const hitsInSafe = findings.filter((f) => f.location?.includes("safe.ts"));
  assert.deepEqual(hitsInSafe, []);
});

test("an empty directory is clean", async () => {
  const dir = await mkdtemp(join(tmpdir(), "keysnag-backdoor-empty-"));
  const result = await backdoorCheck.run({ repoDir: dir, log: () => {} });
  assert.equal(result.ran, true);
  assert.equal(result.findings.length, 0);
});
