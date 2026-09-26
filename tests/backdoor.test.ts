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
import { renderMarkdown } from "../src/report.js";
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

test("LEDGER 13a: the raw hardcoded password never appears in any finding field, or in the rendered markdown report", async () => {
  const RAW_PASSWORD = "letmein123"; // the literal seeded in fixture/backdoor/literal_bypass.ts
  const findings = await runBackdoor();
  const hit = findings.find((f) => f.id === "backdoor.literal_bypass" && f.location?.includes("literal_bypass.ts"));
  assert.ok(hit);
  assert.ok(!hit!.title.includes(RAW_PASSWORD), "title must not echo the raw password");
  assert.ok(!hit!.detail.includes(RAW_PASSWORD), "detail must not echo the raw password");
  assert.ok(!(hit!.evidence ?? "").includes(RAW_PASSWORD), "evidence must not echo the raw password");
  assert.ok(!hit!.fix.includes(RAW_PASSWORD), "fix must not echo the raw password");
  assert.ok(hit!.detail.toLowerCase().includes("password") || hit!.detail.toLowerCase().includes("secret"),
    "detail should still say a password/secret is compared to a hardcoded literal");

  const report = renderMarkdown([{ check: "backdoor", ran: true, findings }]);
  assert.ok(!report.includes(RAW_PASSWORD), "the whole rendered markdown report must never contain the raw password");
});

test("does not fire literal_bypass on typeof-guarded input validation or an empty-string check", async () => {
  const findings = await runBackdoor();
  const hits = findings.filter((f) => f.location?.includes("safe-typeof-literal.ts"));
  assert.deepEqual(hits, [], "typeof apiKey === \"string\" and token === \"\" are not hardcoded bypasses");
});

test("does not fire literal_bypass on role-literal discriminated-union checks", async () => {
  const findings = await runBackdoor();
  const hits = findings.filter((f) => f.location?.includes("safe-role-literal.ts"));
  assert.deepEqual(hits, [], "messages.filter(m => m.role === 'user') and campaigns.find(c => c.role === 'performance') are not backdoors");
});

test("finds the auth-skip flag", async () => {
  const findings = await runBackdoor();
  const hit = findings.find((f) => f.id === "backdoor.auth_skip_flag" && f.location?.includes("auth_skip_flag.ts"));
  assert.ok(hit);
  assert.equal(hit?.severity, "high");
});

test("finds process.env dumped into a response and into a log", async () => {
  const findings = await runBackdoor();
  const hits = findings.filter((f) => f.id === "backdoor.env_dump" && f.location?.includes("env_dump.ts"));
  assert.equal(hits.length, 2);
  for (const hit of hits) assert.equal(hit.severity, "high");
});

test("does not fire env_dump on a local env merge", async () => {
  const findings = await runBackdoor();
  const hits = findings.filter((f) => f.id === "backdoor.env_dump" && f.location?.includes("safe-env-merge.ts"));
  assert.deepEqual(hits, [], "{ ...parseEnvFile(p), ...process.env } assigned to a local const is not a dump");
});

test("does not fire env_dump on a single named process.env property read", async () => {
  const findings = await runBackdoor();
  const hits = findings.filter((f) => f.id === "backdoor.env_dump" && f.location?.includes("safe-env-property.ts"));
  assert.deepEqual(hits, [], "process.env.INTERNAL_JOB_KEY reads one key, not the whole object");
});

test("finds suspicious outbound hosts: raw IP, ngrok tunnel, telegram bot", async () => {
  const findings = await runBackdoor();
  const hits = findings.filter((f) => f.id === "backdoor.suspicious_outbound" && f.location?.includes("suspicious_outbound.ts"));
  assert.equal(hits.length, 3);
  for (const hit of hits) assert.equal(hit.severity, "high");
});

test("does not fire suspicious_outbound on legitimate provider integrations", async () => {
  const findings = await runBackdoor();
  const hits = findings.filter((f) => f.id === "backdoor.suspicious_outbound" && f.location?.includes("safe-outbound.ts"));
  assert.deepEqual(hits, [], "fal.run, api.perplexity.ai, api.amazon.com are legitimate server integrations, not exfil hosts");
});

test("no unexpected_outbound id exists anymore", async () => {
  const findings = await runBackdoor();
  const hit = findings.find((f) => f.id === "backdoor.unexpected_outbound");
  assert.equal(hit, undefined, "backdoor.unexpected_outbound was replaced by backdoor.suspicious_outbound");
});

test("finds the prompt-injection attack phrase inside a string literal", async () => {
  const findings = await runBackdoor();
  const hit = findings.find((f) => f.id === "backdoor.prompt_injection_artifact" && f.location?.includes("prompt_injection_artifact.ts"));
  assert.ok(hit);
  assert.equal(hit?.severity, "low");
});

test("does not fire prompt_injection_artifact on comments/docstrings mentioning 'system prompt'", async () => {
  const findings = await runBackdoor();
  const hits = findings.filter((f) => f.location?.includes("safe-prompt-comment.ts"));
  assert.deepEqual(hits, [], "a comment or docstring about the system prompt is not an injection artifact");
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
