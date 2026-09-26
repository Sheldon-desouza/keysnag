// tests/check-config.test.ts — the `config` check against fixture/config.
// Named check-config (not config.test.ts) because tests/config.test.ts already covers
// src/config.ts (the CLI context loader), a different module.
import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import configCheck from "../src/checks/config.js";
import type { CheckContext, Finding } from "../src/types.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixtureDir = resolve(__dirname, "..", "fixture", "config");

function makeCtx(): CheckContext {
  return { repoDir: fixtureDir, log: () => {} };
}

async function runConfig(): Promise<Finding[]> {
  const result = await configCheck.run(makeCtx());
  assert.equal(result.ran, true);
  return result.findings;
}

const EXPECTED: Array<{ id: string; file: string; severity: string }> = [
  { id: "config.public_env_secret", file: "public-env-secret.env", severity: "critical" },
  { id: "config.service_role_in_client", file: "service-role-in-client.tsx", severity: "high" },
  { id: "config.tls_verification_off", file: "tls-verification-off.ts", severity: "critical" },
  { id: "config.source_maps_prod", file: "source-maps-prod.next.config.js", severity: "high" },
  { id: "config.cors_wildcard_credentials", file: "cors-wildcard-credentials.ts", severity: "high" },
  { id: "config.insecure_cookie", file: "insecure-cookie.ts", severity: "high" },
  { id: "config.weak_random_token", file: "weak-random-token.ts", severity: "high" },
  { id: "config.weak_hash_password", file: "weak-hash-password.ts", severity: "high" },
  { id: "config.hardcoded_jwt_secret", file: "hardcoded-jwt-secret.ts", severity: "high" },
  { id: "config.debug_on", file: ".env.production", severity: "medium" },
];

for (const { id, file, severity } of EXPECTED) {
  test(`${id} fires on ${file}`, async () => {
    const findings = await runConfig();
    const hits = findings.filter((f) => f.id === id && f.location?.includes(file));
    assert.ok(hits.length > 0, `expected ${id} at ${file}, got: ${JSON.stringify(findings.map((f) => [f.id, f.location]))}`);
    for (const h of hits) assert.equal(h.severity, severity, `${id} expected severity ${severity}, got ${h.severity}`);
  });
}

test("each bad fixture fires only its own id, not another check's fixture file", async () => {
  const findings = await runConfig();
  for (const { id, file } of EXPECTED) {
    for (const other of EXPECTED) {
      if (other.file === file) continue;
      const crossHit = findings.find((f) => f.id === other.id && f.location?.includes(file));
      assert.ok(!crossHit, `${other.id} unexpectedly fired on ${file}`);
    }
  }
});

test("the anon key fixture is clean: NEXT_PUBLIC_SUPABASE_ANON_KEY never fires public_env_secret", async () => {
  const findings = await runConfig();
  const hit = findings.find((f) => f.location?.includes("safe-anon-key.env"));
  assert.equal(hit, undefined, `expected no findings on safe-anon-key.env, got: ${JSON.stringify(hit)}`);
});

test("safe.ts (crypto.randomUUID, bcrypt-style sha256+salt, env-var JWT secret, correct cookie flags) is clean", async () => {
  const findings = await runConfig();
  const hits = findings.filter((f) => f.location?.includes("/safe.ts:") || f.location?.startsWith("safe.ts:"));
  assert.deepEqual(hits, [], `expected no findings on safe.ts, got: ${JSON.stringify(hits)}`);
});

test("an empty directory yields no findings", async () => {
  const dir = await mkdtemp(join(tmpdir(), "keysnag-config-empty-"));
  try {
    const result = await configCheck.run({ repoDir: dir, log: () => {} });
    assert.equal(result.ran, true);
    assert.deepEqual(result.findings, []);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("honours ctx.changedFiles: scanning an unrelated changed file finds nothing", async () => {
  const result = await configCheck.run({
    repoDir: fixtureDir,
    changedFiles: ["safe.ts"],
    log: () => {},
  });
  assert.equal(result.ran, true);
  const hits = result.findings.filter((f) => f.location?.includes("tls-verification-off.ts"));
  assert.deepEqual(hits, [], "changedFiles scope should not pull in files outside the list");
});
