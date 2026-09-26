// tests/authz.test.ts — runs the real `authz` check against the seeded
// fixture/authz/ routes (no network) and asserts each rule fires exactly for its
// bad file and not for the correctly-guarded one, plus a clean run on an empty dir.
// authz is not yet registered in src/checks/index.ts (item 8's job), so it is
// imported directly here.
import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import authzCheck from "../src/checks/authz.js";
import type { CheckContext, Finding } from "../src/types.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixtureDir = resolve(__dirname, "..", "fixture", "authz");

function makeCtx(repoDir: string): CheckContext {
  return { repoDir, log: () => {} };
}

async function runAuthz(): Promise<Finding[]> {
  const result = await authzCheck.run(makeCtx(fixtureDir));
  assert.equal(result.ran, true);
  return result.findings;
}

test("authz.route_without_auth fires on a route that queries the DB with no auth check", async () => {
  const findings = await runAuthz();
  const hit = findings.find(
    (f) => f.id === "authz.route_without_auth" && f.location?.includes("bad-no-auth/"),
  );
  assert.ok(hit, "expected authz.route_without_auth on bad-no-auth/app/api/orders/route.ts");
  assert.equal(hit!.severity, "high", "read-only unauthenticated route should be high, not critical");
});

test("authz.route_without_auth is critical when the unauthenticated route also writes", async () => {
  const findings = await runAuthz();
  const hit = findings.find(
    (f) => f.id === "authz.route_without_auth" && f.location?.includes("bad-write-no-auth/"),
  );
  assert.ok(hit, "expected authz.route_without_auth on bad-write-no-auth/app/api/reports/route.ts");
  assert.equal(hit!.severity, "critical", "unauthenticated route that also deletes should be critical");
});

test("authz.client_supplied_identity fires when a query is filtered by an id read from the request", async () => {
  const findings = await runAuthz();
  const hit = findings.find(
    (f) => f.id === "authz.client_supplied_identity" && f.location?.includes("bad-client-identity/"),
  );
  assert.ok(hit, "expected authz.client_supplied_identity on bad-client-identity/app/api/profile/route.ts");
  assert.equal(hit!.severity, "high");
});

test("authz.admin_route_no_role_check fires on an /admin route with no role check", async () => {
  const findings = await runAuthz();
  const hit = findings.find(
    (f) => f.id === "authz.admin_route_no_role_check" && f.location?.includes("bad-admin/"),
  );
  assert.ok(hit, "expected authz.admin_route_no_role_check on bad-admin/app/api/admin/users/route.ts");
  assert.equal(hit!.severity, "high");
});

test("a correctly-guarded route trips no authz finding", async () => {
  const findings = await runAuthz();
  const hits = findings.filter((f) => f.location?.includes("good/"));
  assert.deepEqual(hits, [], `expected no findings on good/app/api/orders/route.ts, got ${JSON.stringify(hits)}`);
});

test("skips cleanly on an empty directory with no matching routes", async () => {
  const dir = mkdtempSync(join(tmpdir(), "keysnag-authz-empty-"));
  try {
    const result = await authzCheck.run(makeCtx(dir));
    assert.equal(result.ran, true);
    assert.deepEqual(result.findings, []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
