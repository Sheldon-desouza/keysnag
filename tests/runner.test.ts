// tests/runner.test.ts — a check with a missing `requires` field is skipped (never thrown),
// and a check that throws becomes an info finding instead of crashing the harness.
import { test } from "node:test";
import assert from "node:assert/strict";
import type { Check, CheckContext } from "../src/types.js";
import { runChecks } from "../src/runner.js";
import rlsCheck from "../src/checks/rls.js";
import twoaccountCheck from "../src/checks/twoaccount.js";
import urlprobeCheck from "../src/checks/urlprobe.js";

function makeCtx(overrides: Partial<CheckContext> = {}): CheckContext {
  return { log: () => {}, ...overrides };
}

test("a check whose requires field is absent from context is skipped, naming the reason", async () => {
  const check: Check = {
    name: "needs-pg",
    description: "a check that requires pgUrl",
    requires: ["pgUrl"],
    async run() {
      throw new Error("should never be called when pgUrl is missing");
    },
  };

  const results = await runChecks(makeCtx(), [check]);
  assert.equal(results.length, 1);
  assert.equal(results[0].ran, false);
  assert.match(results[0].skippedReason ?? "", /KEYSNAG_PG_URL/);
  assert.deepEqual(results[0].findings, []);
});

test("a check that throws becomes an info finding and does not throw out of runChecks", async () => {
  const check: Check = {
    name: "explodes",
    description: "a check that throws",
    requires: [],
    async run() {
      throw new Error("boom");
    },
  };

  const results = await runChecks(makeCtx(), [check]);
  assert.equal(results.length, 1);
  assert.equal(results[0].ran, false);
  assert.equal(results[0].findings.length, 1);
  assert.equal(results[0].findings[0].severity, "info");
  assert.match(results[0].findings[0].detail, /boom/);
});

test("rls, twoaccount, and urlprobe all skip cleanly with an empty context (no network, no DB)", async () => {
  const results = await runChecks(makeCtx(), [rlsCheck, twoaccountCheck, urlprobeCheck]);
  assert.equal(results.length, 3);
  for (const r of results) {
    assert.equal(r.ran, false, `expected ${r.check} to skip with an empty context`);
    assert.ok(r.skippedReason, `expected ${r.check} to name a skip reason`);
    assert.deepEqual(r.findings, []);
  }
});
