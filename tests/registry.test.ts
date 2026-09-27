// tests/registry.test.ts — src/checks/index.ts must export exactly the 13 shipped
// checks, each with a unique name, and each `requires` list must only name real
// CheckContext keys (so a typo in a check's `requires` array is caught here, not
// silently skipping the check forever at runtime).
import { test } from "node:test";
import assert from "node:assert/strict";
import { checks } from "../src/checks/index.js";
import type { CheckContext } from "../src/types.js";

// The non-function keys of CheckContext a check's `requires` array is allowed to name.
// `log` is not something a check requires (it's always present), so it's excluded.
const CHECK_CONTEXT_KEYS: ReadonlySet<keyof CheckContext> = new Set([
  "repoDir",
  "siteUrl",
  "supabaseUrl",
  "supabaseAnonKey",
  "pgUrl",
  "tokenA",
  "tokenB",
  "changedFiles",
  "allowOsv",
  "privateTerms",
]);

test("exactly 13 checks are registered", () => {
  assert.equal(checks.length, 13);
});

test("every check has a unique name", () => {
  const names = checks.map((c) => c.name);
  assert.equal(new Set(names).size, names.length, `duplicate check names in: ${names.join(", ")}`);
});

test("every check's `requires` list only names real CheckContext keys", () => {
  for (const check of checks) {
    for (const key of check.requires) {
      assert.ok(
        CHECK_CONTEXT_KEYS.has(key),
        `check "${check.name}" requires unknown CheckContext key "${String(key)}"`,
      );
    }
  }
});

test("all 12 expected check names are present", () => {
  const names = new Set(checks.map((c) => c.name));
  for (const expected of [
    "secrets",
    "config",
    "authz",
    "injection",
    "payments",
    "backdoor",
    "ai-endpoints",
    "deps",
    "storage",
    "urlprobe",
    "rls",
    "twoaccount",
  ]) {
    assert.ok(names.has(expected), `expected registered check "${expected}"`);
  }
});
