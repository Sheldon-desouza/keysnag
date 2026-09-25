// tests/secrets.test.ts — the key integration test. Runs the real `secrets` check against
// the seeded fixture repo (no network, no DB) and asserts every seeded secret fires, evidence
// is always masked, and client-file/committed-.env hits come back critical.
import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import secretsCheck from "../src/checks/secrets.js";
import type { CheckContext, Finding } from "../src/types.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixtureDir = resolve(__dirname, "..", "fixture");

function makeCtx(): CheckContext {
  return { repoDir: fixtureDir, log: () => {} };
}

async function runSecrets(): Promise<Finding[]> {
  const result = await secretsCheck.run(makeCtx());
  assert.equal(result.ran, true);
  return result.findings;
}

test("finds the seeded Supabase service_role JWT", async () => {
  const findings = await runSecrets();
  const hit = findings.find((f) => f.id === "secret.supabase_service_role");
  assert.ok(hit, "expected a secret.supabase_service_role finding");
});

test("finds the seeded Stripe sk_live key", async () => {
  const findings = await runSecrets();
  const hit = findings.find((f) => f.id.startsWith("secret.stripe_key"));
  assert.ok(hit, "expected a secret.stripe_key finding");
});

test("finds the seeded OpenAI key", async () => {
  const findings = await runSecrets();
  const hit = findings.find((f) => f.id.startsWith("secret.openai_key"));
  assert.ok(hit, "expected a secret.openai_key finding");
});

test("evidence is always masked, never a full live secret value", async () => {
  const findings = await runSecrets();
  assert.ok(findings.length > 0, "expected at least one finding to check evidence on");
  for (const f of findings) {
    if (!f.evidence) continue;
    // masked shape is "first4…last4 (N chars)" or the literal "****" for short values.
    assert.ok(
      f.evidence === "****" || /^.{1,4}….{1,4} \(\d+ chars\)$/.test(f.evidence),
      `evidence "${f.evidence}" does not look masked`,
    );
    // never the raw fixture secret substrings in full
    assert.ok(!f.evidence.includes("sk_live_"), "evidence must not contain a raw live key prefix run-on");
  }
});

test("a hit in a client-shipped file (.tsx) or a committed .env is severity critical", async () => {
  // The secrets check treats .tsx/.jsx and committed .env files as client-shipped/exposed;
  // a plain .ts lib file (e.g. fixture/lib/supabaseClient.ts) is not, by the check's own rule.
  const findings = await runSecrets();
  const clientOrEnvHits = findings.filter(
    (f) => f.location?.includes("page.tsx") || f.location?.includes(".env.local"),
  );
  assert.ok(clientOrEnvHits.length > 0, "expected at least one finding located in page.tsx or .env.local");
  for (const f of clientOrEnvHits) {
    assert.equal(f.severity, "critical", `expected critical for ${f.id} at ${f.location}`);
  }
});
