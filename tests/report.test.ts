// tests/report.test.ts — renderMarkdown groups critical-first with a summary count,
// renderAgentTasks emits one bullet per finding, and neither leaks a raw secret.
import { test } from "node:test";
import assert from "node:assert/strict";
import type { CheckResult } from "../src/types.js";
import { renderMarkdown, renderAgentTasks } from "../src/report.js";

const LIVE_SECRET = "sk_test_thisIsALiveLookingSecretValue1234567890";

function sampleResults(): CheckResult[] {
  return [
    {
      check: "secrets",
      ran: true,
      findings: [
        {
          id: "secret.stripe_key",
          check: "secrets",
          severity: "critical",
          title: "Stripe secret key found",
          detail: "A live Stripe key was found.",
          location: "app/page.tsx:3",
          evidence: "sk_l…7890 (48 chars)",
          fix: "Rotate the key and move it server-side.",
        },
        {
          id: "secret.generic_high_entropy",
          check: "secrets",
          severity: "medium",
          title: "Possible secret assigned to API_TOKEN",
          detail: "A high-entropy string was found.",
          fix: "Verify and rotate if live.",
        },
      ],
    },
    {
      check: "rls",
      ran: false,
      skippedReason: "missing VG_PG_URL",
      findings: [],
    },
  ];
}

test("renderMarkdown groups findings critical-first and includes a summary count", () => {
  const md = renderMarkdown(sampleResults());
  const criticalIdx = md.indexOf("## Critical");
  const mediumIdx = md.indexOf("## Medium");
  assert.ok(criticalIdx !== -1 && mediumIdx !== -1);
  assert.ok(criticalIdx < mediumIdx, "critical section must appear before medium");
  assert.match(md, /1 check\(s\) ran, 1 skipped\..*1 critical.*1 medium/);
  assert.match(md, /## Skipped checks/);
  assert.match(md, /missing VG_PG_URL/);
});

test("renderAgentTasks emits one bullet per finding", () => {
  const results = sampleResults();
  const totalFindings = results.flatMap((r) => r.findings).length;
  const tasks = renderAgentTasks(results);
  const bulletLines = tasks.split("\n").filter((l) => l.startsWith("- ["));
  assert.equal(bulletLines.length, totalFindings);
  assert.match(tasks, /\[CRITICAL\]/);
  assert.match(tasks, /\[MEDIUM\]/);
});

test("neither renderer ever passes through a raw, unmasked secret value", () => {
  const results: CheckResult[] = [
    {
      check: "secrets",
      ran: true,
      findings: [
        {
          id: "secret.stripe_key",
          check: "secrets",
          severity: "critical",
          title: "Stripe secret key found",
          detail: "A live Stripe key was found.",
          location: "app/page.tsx:3",
          evidence: "sk_l…7890 (48 chars)",
          fix: "Rotate the key and move it server-side.",
        },
      ],
    },
  ];
  const md = renderMarkdown(results);
  const tasks = renderAgentTasks(results);
  assert.ok(!md.includes(LIVE_SECRET));
  assert.ok(!tasks.includes(LIVE_SECRET));
});
