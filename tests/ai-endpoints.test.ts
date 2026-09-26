// tests/ai-endpoints.test.ts — runs the real `ai-endpoints` check against the seeded
// fixture (no network) and asserts each seeded flaw fires only its own id.
import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import aiCheck from "../src/checks/ai-endpoints.js";
import type { CheckContext, Finding } from "../src/types.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixtureDir = resolve(__dirname, "..", "fixture", "ai");

function makeCtx(): CheckContext {
  return { repoDir: fixtureDir, log: () => {} };
}

async function runAi(): Promise<Finding[]> {
  const result = await aiCheck.run(makeCtx());
  assert.equal(result.ran, true);
  return result.findings;
}

test("requires is empty", () => {
  assert.deepEqual(aiCheck.requires, []);
});

test("finds an LLM SDK called from a client component", async () => {
  const findings = await runAi();
  const hit = findings.find((f) => f.id === "ai.llm_call_in_client" && f.location?.includes("ChatWidget.tsx"));
  assert.ok(hit);
  assert.equal(hit?.severity, "critical");
});

test("finds an LLM route with no auth check", async () => {
  const findings = await runAi();
  const hit = findings.find((f) => f.id === "ai.llm_route_no_auth" && f.location?.includes("app/api/chat/route.ts"));
  assert.ok(hit);
  assert.equal(hit?.severity, "high");
  // this fixture has a rate limiter, so it must not also trip no_spend_bound
  const spendHit = findings.find((f) => f.id === "ai.llm_route_no_spend_bound" && f.location?.includes("app/api/chat/route.ts"));
  assert.equal(spendHit, undefined);
});

test("finds an LLM route with no spend bound, severity high when auth is present", async () => {
  const findings = await runAi();
  const hit = findings.find(
    (f) => f.id === "ai.llm_route_no_spend_bound" && f.location?.includes("chat-nospendbound/route.ts"),
  );
  assert.ok(hit);
  assert.equal(hit?.severity, "high");
});

test("finds a raw user prompt built from request body", async () => {
  const findings = await runAi();
  const hit = findings.find((f) => f.id === "ai.raw_user_prompt" && f.location?.includes("chat-rawprompt/route.ts"));
  assert.ok(hit);
  assert.equal(hit?.severity, "low");
});

test("finds LLM output rendered as HTML with no sanitiser", async () => {
  const findings = await runAi();
  const hit = findings.find((f) => f.id === "ai.unsafe_output_render" && f.location?.includes("UnsafeAnswer.tsx"));
  assert.ok(hit);
  assert.equal(hit?.severity, "high");
});

test("does not flag output rendering that goes through DOMPurify.sanitize", async () => {
  const findings = await runAi();
  const hit = findings.find((f) => f.id === "ai.unsafe_output_render" && f.location?.includes("SafeAnswer.tsx"));
  assert.equal(hit, undefined);
});

test("does not flag a static page's JSON-LD idiom (__html: JSON.stringify), no LLM anywhere", async () => {
  const findings = await runAi();
  const hits = findings.filter((f) => f.location?.includes("safe-static-jsonld.tsx"));
  assert.deepEqual(hits, []);
});

test("does not flag a marketing page rendering pre-authored HTML with no LLM import", async () => {
  const findings = await runAi();
  const hits = findings.filter((f) => f.location?.includes("safe-landing.tsx"));
  assert.deepEqual(hits, []);
});

test("the fully safe route (auth + rate limit + templated prompt) is clean", async () => {
  const findings = await runAi();
  const hitsInSafeRoute = findings.filter((f) => f.location?.includes("chat-safe/route.ts"));
  assert.deepEqual(hitsInSafeRoute, []);
});

test("an empty directory is clean", async () => {
  const dir = await mkdtemp(join(tmpdir(), "keysnag-ai-empty-"));
  const result = await aiCheck.run({ repoDir: dir, log: () => {} });
  assert.equal(result.ran, true);
  assert.equal(result.findings.length, 0);
});
