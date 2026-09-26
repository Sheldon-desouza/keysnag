// tests/check-payments.test.ts — the `payments` check against fixture/payments.
import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { dirname, resolve, join } from "node:path";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import paymentsCheck from "../src/checks/payments.js";
import type { CheckContext, Finding } from "../src/types.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixtureDir = resolve(__dirname, "..", "fixture", "payments");

function makeCtx(): CheckContext {
  return { repoDir: fixtureDir, log: () => {} };
}

async function runPayments(): Promise<Finding[]> {
  const result = await paymentsCheck.run(makeCtx());
  assert.equal(result.ran, true);
  return result.findings;
}

test("payments.webhook_unverified fires on the unverified webhook fixture, critical", async () => {
  const findings = await runPayments();
  const hits = findings.filter((f) => f.id === "payments.webhook_unverified" && f.location?.includes("webhook-unverified.ts"));
  assert.ok(hits.length > 0, "expected payments.webhook_unverified on webhook-unverified.ts");
  for (const h of hits) assert.equal(h.severity, "critical");
});

test("payments.client_priced_charge fires when amount/currency come from the request body, critical", async () => {
  const findings = await runPayments();
  const hits = findings.filter((f) => f.id === "payments.client_priced_charge" && f.location?.includes("client-priced-charge.ts"));
  assert.ok(hits.length > 0, "expected payments.client_priced_charge on client-priced-charge.ts");
  for (const h of hits) assert.equal(h.severity, "critical");
});

test("payments.no_idempotency fires on a charges.create with no idempotencyKey, low", async () => {
  const findings = await runPayments();
  const hits = findings.filter((f) => f.id === "payments.no_idempotency" && f.location?.includes("no-idempotency.ts"));
  assert.ok(hits.length > 0, "expected payments.no_idempotency on no-idempotency.ts");
  for (const h of hits) assert.equal(h.severity, "low");
});

test("no-idempotency fixture is not also flagged as client-priced (its amount is a server-side lookup)", async () => {
  const findings = await runPayments();
  const hits = findings.filter((f) => f.id === "payments.client_priced_charge" && f.location?.includes("no-idempotency.ts"));
  assert.deepEqual(hits, []);
});

test("safe.ts (verified webhook + server-side price lookup + idempotencyKey) is clean", async () => {
  const findings = await runPayments();
  const hits = findings.filter((f) => f.location?.includes("safe.ts"));
  assert.deepEqual(hits, [], `expected no findings on safe.ts, got: ${JSON.stringify(hits)}`);
});

test("docs-example.md (markdown showing the vulnerable snippet) is skipped: source-extensions-only", async () => {
  const findings = await runPayments();
  const hits = findings.filter((f) => f.location?.includes("docs-example.md"));
  assert.deepEqual(hits, [], `expected no findings on docs-example.md, got: ${JSON.stringify(hits)}`);
});

test("safe-shopify-webhook route (verifies via a sibling lib import) is clean, and the lib file itself never fires", async () => {
  const findings = await runPayments();
  const hits = findings.filter((f) => f.location?.includes("safe-shopify-webhook"));
  assert.deepEqual(hits, [], `expected no findings under safe-shopify-webhook, got: ${JSON.stringify(hits)}`);
});

test("safe-tiktok-webhook route (verifies via a sibling lib import + x-tiktok-signature) is clean, and the lib file itself never fires", async () => {
  const findings = await runPayments();
  const hits = findings.filter((f) => f.location?.includes("safe-tiktok-webhook"));
  assert.deepEqual(hits, [], `expected no findings under safe-tiktok-webhook, got: ${JSON.stringify(hits)}`);
});

test("an empty directory yields no findings", async () => {
  const dir = await mkdtemp(join(tmpdir(), "keysnag-payments-empty-"));
  try {
    const result = await paymentsCheck.run({ repoDir: dir, log: () => {} });
    assert.equal(result.ran, true);
    assert.deepEqual(result.findings, []);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("honours ctx.changedFiles: scanning only the safe file finds nothing", async () => {
  const result = await paymentsCheck.run({
    repoDir: fixtureDir,
    changedFiles: ["safe.ts"],
    log: () => {},
  });
  assert.equal(result.ran, true);
  assert.deepEqual(result.findings, []);
});

test("skips conventional test/mock dirs of the scanned repo", async () => {
  const dir = await mkdtemp(join(tmpdir(), "keysnag-payments-testdir-"));
  try {
    const { mkdir, writeFile } = await import("node:fs/promises");
    await mkdir(join(dir, "__tests__"), { recursive: true });
    await writeFile(
      join(dir, "__tests__", "webhook.route.ts"),
      "export async function POST(request: Request) { const event = await request.json(); return new Response('ok'); }",
      "utf8",
    );
    const result = await paymentsCheck.run({ repoDir: dir, log: () => {} });
    assert.deepEqual(result.findings, []);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
