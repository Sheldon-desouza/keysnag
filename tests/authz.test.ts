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
  // LEDGER item 11 (I): must report the line of the matched identity read
  // (searchParams.get("userId") on line 11), not line 1 (the import).
  assert.equal(hit!.location, "bad-client-identity/app/api/profile/route.ts:11");
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

// LEDGER item 11 (I): a real admin route that imports and calls requireAdmin()
// before writing must trip no finding at all (requireAdmin is both an auth
// signal and a role-check signal).
test("an admin route guarded by requireAdmin() trips no authz finding", async () => {
  const findings = await runAuthz();
  const hits = findings.filter((f) => f.location?.includes("safe-require-admin/"));
  assert.deepEqual(hits, [], `expected no findings on safe-require-admin route, got ${JSON.stringify(hits)}`);
});

// LEDGER item 11 (I): auth-flow routes under /api/auth/ are public by design
// (rate-limited elsewhere) and must be skipped entirely.
test("a route under /api/auth/ trips no authz finding", async () => {
  const findings = await runAuthz();
  const hits = findings.filter((f) => f.location?.includes("safe-auth-flow/"));
  assert.deepEqual(hits, [], `expected no findings on safe-auth-flow/app/api/auth/check-confirmed/route.ts, got ${JSON.stringify(hits)}`);
});

// LEDGER item 11 (I) precision risk: admin_route_no_role_check must strip
// comments before matching, so a comment-only mention of "admin"/"role" does
// not suppress a real finding.
test("admin_route_no_role_check fires even when the only admin/role mention is in a comment", async () => {
  const findings = await runAuthz();
  const hit = findings.find(
    (f) => f.id === "authz.admin_route_no_role_check" && f.location?.includes("safe-comment-mention/"),
  );
  assert.ok(hit, "expected authz.admin_route_no_role_check on safe-comment-mention/app/api/admin/x/route.ts");
});

// LEDGER item 13c: the bare word "admin" in an import path (@/lib/admin-utils) or
// the route path itself is not a role check. Must still fire, at the exported
// handler's line, not always :1.
test("admin_route_no_role_check fires when the only 'admin' mention is the import path, at the handler line", async () => {
  const findings = await runAuthz();
  const hit = findings.find(
    (f) => f.id === "authz.admin_route_no_role_check" && f.location?.includes("bad-admin-import-only/"),
  );
  assert.ok(hit, "expected authz.admin_route_no_role_check on bad-admin-import-only/app/api/admin/dashboard/route.ts");
  assert.equal(
    hit!.location,
    "bad-admin-import-only/app/api/admin/dashboard/route.ts:10",
    "location must be the line of the exported GET handler",
  );
});

// LEDGER item 13d: requireRole('editor') is not an operator gate.
test("client_supplied_identity fires under requireRole('editor')", async () => {
  const findings = await runAuthz();
  const hit = findings.find(
    (f) => f.id === "authz.client_supplied_identity" && f.location?.includes("bad-client-identity-editor-role/"),
  );
  assert.ok(hit, "expected authz.client_supplied_identity on bad-client-identity-editor-role, requireRole('editor') is not an operator gate");
});

// LEDGER item 13d: requireRole('admin') IS an operator gate.
test("client_supplied_identity does not fire under requireRole('admin')", async () => {
  const findings = await runAuthz();
  const hits = findings.filter(
    (f) => f.id === "authz.client_supplied_identity" && f.location?.includes("safe-client-identity-admin-role/"),
  );
  assert.deepEqual(hits, [], "requireRole('admin') is an operator gate for a client-supplied identity");
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

test("an admin-gated operator route acting on another user's id does NOT trip client_supplied_identity", async () => {
  const authz = (await import("../src/checks/authz.js")).default;
  const res = await authz.run({ repoDir: "./fixture/authz/safe-admin-repair", log: () => {} });
  const hit = res.findings.find((f) => f.id === "authz.client_supplied_identity");
  assert.equal(hit, undefined, `should not fire on an admin-gated route: ${JSON.stringify(res.findings.map((f) => f.id))}`);
});

test("createAdminClient() is a service client, not a role check: /api/admin route with only getUser MUST fire admin_route_no_role_check (verify cycle 2)", async () => {
  const authz = (await import("../src/checks/authz.js")).default;
  const res = await authz.run({ repoDir: "./fixture/authz/bad-admin-service-client", log: () => {} });
  const hit = res.findings.find((f) => f.id === "authz.admin_route_no_role_check");
  assert.ok(hit, `expected admin_route_no_role_check, got ${JSON.stringify(res.findings.map((f) => f.id))}`);
  assert.match(hit!.location ?? "", /route\.ts:7$/, "location should be the exported handler line");
});
