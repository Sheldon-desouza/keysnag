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
  // The secrets check treats .tsx/.jsx and committed .env files as client-shipped/exposed.
  const findings = await runSecrets();
  const clientOrEnvHits = findings.filter(
    (f) => f.location?.includes("page.tsx") || f.location?.includes(".env.local"),
  );
  assert.ok(clientOrEnvHits.length > 0, "expected at least one finding located in page.tsx or .env.local");
  for (const f of clientOrEnvHits) {
    assert.equal(f.severity, "critical", `expected critical for ${f.id} at ${f.location}`);
  }
});

test("a service_role JWT is critical even in a plain .ts file (bypasses RLS anywhere)", async () => {
  const findings = await runSecrets();
  const svc = findings.filter((f) => f.id === "secret.supabase_service_role");
  assert.ok(svc.length > 0, "expected service_role findings");
  for (const f of svc) {
    assert.equal(f.severity, "critical", `service_role must be critical, got ${f.severity} at ${f.location}`);
  }
});

test("a value caught by a specific rule is not also double-reported as generic high-entropy", async () => {
  const findings = await runSecrets();
  const byLocation = new Map<string, string[]>();
  for (const f of findings) {
    const key = f.location ?? "";
    byLocation.set(key, [...(byLocation.get(key) ?? []), f.id]);
  }
  for (const [loc, ids] of byLocation) {
    if (ids.some((id) => id.startsWith("secret.stripe_key") || id.startsWith("secret.openai_key"))) {
      assert.ok(!ids.includes("secret.generic_high_entropy"), `duplicate generic hit at ${loc}: ${ids.join(", ")}`);
    }
  }
});

// Regression tests from dogfooding on a real repo (2026-09-25): the generic rule
// was flagging storage-key names, config slugs and MIME types as secrets.
test("does NOT flag storage-key names, config slugs, or MIME types (real-repo false positives)", async () => {
  const { mkdtemp, writeFile, mkdir } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const dir = await mkdtemp(join(tmpdir(), "keysnag-fp-"));
  await writeFile(
    join(dir, "sample.ts"),
    [
      "const STORAGE_KEY = 'app_active_brand';",
      "const COOKIE_KEY = 'app_active_brand';",
      "const LTD_BANNER_DISMISSED_KEY = 'ltd_banner_dismissed';",
      "const KEYWORDS_REC_V5 = 'application/vnd.spkeywordsrecommendation.v5+json';",
      "const ANALYTICS_CONSENT_KEY = 'analytics_consent_v2';",
    ].join("\n"),
    "utf8",
  );
  const secrets = (await import("../src/checks/secrets.js")).default;
  const res = await secrets.run({ repoDir: dir, log: () => {} });
  assert.equal(res.findings.length, 0, `expected no findings, got: ${JSON.stringify(res.findings.map((f) => f.title))}`);
});

test("STILL flags a genuine high-entropy secret assigned to a *_KEY identifier", async () => {
  const { mkdtemp, writeFile } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const dir = await mkdtemp(join(tmpdir(), "keysnag-tp-"));
  await writeFile(join(dir, "config.ts"), "const API_SECRET_KEY = 'xR9-Kf2mQ7wZ1pL8vB4nT6yH0aE3sD5cG';", "utf8");
  const secrets = (await import("../src/checks/secrets.js")).default;
  const res = await secrets.run({ repoDir: dir, log: () => {} });
  assert.ok(res.findings.some((f) => f.id === "secret.generic_high_entropy"), "expected the real secret to be flagged");
});
