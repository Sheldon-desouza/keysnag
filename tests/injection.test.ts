// tests/injection.test.ts — runs the real `injection` check against the seeded
// fixture/injection files (no network, no DB) and asserts each id fires only for
// its own bad fixture, the safe fixture is clean, and an empty dir yields nothing.
import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import injectionCheck from "../src/checks/injection.js";
import type { CheckContext, Finding } from "../src/types.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixtureDir = resolve(__dirname, "..", "fixture", "injection");

function makeCtx(dir: string): CheckContext {
  return { repoDir: dir, log: () => {} };
}

async function runInjection(dir: string): Promise<Finding[]> {
  const result = await injectionCheck.run(makeCtx(dir));
  assert.equal(result.ran, true);
  return result.findings;
}

const RULE_TO_FILE: Record<string, string> = {
  "injection.sql_concat": "sql-concat.ts",
  "injection.dangerous_html": "dangerous-html.tsx",
  "injection.eval": "eval.ts",
  "injection.command": "command.ts",
  "injection.ssrf": "ssrf.ts",
  "injection.path_traversal": "path-traversal.ts",
  "injection.proto_pollution": "proto-pollution.ts",
};

test("every rule fires only for its own bad fixture", async () => {
  const findings = await runInjection(fixtureDir);
  for (const [id, file] of Object.entries(RULE_TO_FILE)) {
    const hits = findings.filter((f) => f.id === id);
    assert.ok(hits.length > 0, `expected at least one ${id} finding`);
    for (const hit of hits) {
      assert.ok(hit.location?.includes(file), `${id} fired at ${hit.location}, expected it in ${file}`);
    }
  }
});

test("critical severity for request-derived sql_concat/eval/command", async () => {
  const findings = await runInjection(fixtureDir);
  for (const id of ["injection.sql_concat", "injection.eval", "injection.command"]) {
    const hit = findings.find((f) => f.id === id);
    assert.ok(hit, `expected a ${id} finding`);
    assert.equal(hit!.severity, "critical", `expected ${id} to be critical, got ${hit!.severity}`);
  }
});

test("ssrf and path_traversal fire critical with no guard nearby", async () => {
  const findings = await runInjection(fixtureDir);
  for (const id of ["injection.ssrf", "injection.path_traversal"]) {
    const hit = findings.find((f) => f.id === id);
    assert.ok(hit, `expected a ${id} finding`);
    assert.equal(hit!.severity, "critical", `expected ${id} to be critical (no guard), got ${hit!.severity}`);
  }
});

test("dangerous_html is high, proto_pollution is medium", async () => {
  const findings = await runInjection(fixtureDir);
  const html = findings.find((f) => f.id === "injection.dangerous_html");
  assert.ok(html);
  assert.equal(html!.severity, "high");
  const proto = findings.find((f) => f.id === "injection.proto_pollution");
  assert.ok(proto);
  assert.equal(proto!.severity, "medium");
});

test("the safe fixture trips no injection rule", async () => {
  const findings = await runInjection(fixtureDir);
  const safeHits = findings.filter((f) => f.location?.includes("safe.ts"));
  assert.equal(safeHits.length, 0, `expected no findings in safe.ts, got: ${JSON.stringify(safeHits)}`);
});

test("findings are deduped one per (rule,file,line)", async () => {
  const findings = await runInjection(fixtureDir);
  const seen = new Set<string>();
  for (const f of findings) {
    const key = `${f.id}|${f.location}`;
    assert.ok(!seen.has(key), `duplicate finding for ${key}`);
    seen.add(key);
  }
});

test("an empty directory yields no findings", async () => {
  const dir = await mkdtemp(join(tmpdir(), "keysnag-injection-empty-"));
  const findings = await runInjection(dir);
  assert.equal(findings.length, 0);
});

test("skips test/spec/fixture files and .d.ts", async () => {
  const { mkdir, writeFile } = await import("node:fs/promises");
  const dir = await mkdtemp(join(tmpdir(), "keysnag-injection-skip-"));
  await mkdir(join(dir, "__tests__"), { recursive: true });
  await writeFile(join(dir, "bad.test.ts"), "eval(req.body.x);", "utf8");
  await writeFile(join(dir, "__tests__", "bad.ts"), "eval(req.body.x);", "utf8");
  await writeFile(join(dir, "bad.d.ts"), "eval(req.body.x);", "utf8");
  const findings = await runInjection(dir);
  assert.equal(findings.length, 0, `expected skipped files to yield nothing, got: ${JSON.stringify(findings)}`);
});
