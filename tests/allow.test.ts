// tests/allow.test.ts — the exceptions baseline: matching, apply, validation, and the CLI helper.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { applyAllowList, validateAllowList, loadAllowList } from "../src/allow.js";
import { exitCodeForFindings } from "../src/gate.js";
import type { CheckResult } from "../src/types.js";

const CLI = resolve(process.cwd(), "dist/cli.js");

function makeTmpDir(): string {
  return mkdtempSync(join(tmpdir(), "keysnag-allow-test-"));
}

function findingResult(id: string, location: string, title = "A finding"): CheckResult[] {
  return [
    {
      check: id.split(".")[0],
      ran: true,
      findings: [
        {
          id,
          check: id.split(".")[0],
          severity: "critical",
          title,
          detail: "It matched.",
          location,
          fix: "Do the thing.",
        },
      ],
    },
  ];
}

test("applyAllowList downgrades an exact match to info with the [allowed] prefix and appended reason/bound", () => {
  const results = findingResult("secret.stripe_key", "src/app/api/foo/route.ts:10");
  const allowed = applyAllowList(results, [
    {
      id: "secret.stripe_key",
      location: "src/app/api/foo/route.ts:10",
      reason: "Test fixture key, not live",
      bound: "no user data",
    },
  ]);

  const finding = allowed[0].findings[0];
  assert.equal(finding.severity, "info");
  assert.match(finding.title, /^\[allowed\] /);
  assert.match(finding.detail, /Allowed: Test fixture key, not live\. Bound: no user data\./);

  assert.equal(exitCodeForFindings(allowed, "critical"), 0, "allowed finding must not block");
  assert.equal(exitCodeForFindings(results, "critical"), 2, "sanity: unallowed finding does block");
});

test("id matches by prefix, location matches by file part before the line number", () => {
  const results = findingResult("secret.stripe_key.extra", "src/app/api/foo/route.ts:42");
  const allowed = applyAllowList(results, [
    { id: "secret.", location: "src/app/api/foo/route.ts", reason: "why", bound: "how" },
  ]);
  assert.equal(allowed[0].findings[0].severity, "info");
});

test("glob location matches with * and **", () => {
  const results = findingResult("authz.route_without_auth", "src/app/api/admin/users/route.ts:5");
  const allowed = applyAllowList(results, [
    { id: "authz.route_without_auth", location: "src/app/api/**/route.ts", reason: "why", bound: "how" },
  ]);
  assert.equal(allowed[0].findings[0].severity, "info");
});

test("a finding that does not match any entry is left untouched", () => {
  const results = findingResult("secret.stripe_key", "src/app/api/foo/route.ts:10");
  const allowed = applyAllowList(results, [
    { id: "secret.openai_key", location: "src/app/api/foo/route.ts:10", reason: "why", bound: "how" },
  ]);
  assert.equal(allowed[0].findings[0].severity, "critical");
  assert.equal(allowed[0].findings[0].title, "A finding");
});

test("validateAllowList throws naming an entry missing reason and/or bound", () => {
  assert.throws(
    () =>
      validateAllowList([
        { id: "a", location: "b", reason: "", bound: "x" },
        { id: "c", location: "d", reason: "y", bound: "" },
      ]),
    (err: unknown) => {
      const message = err instanceof Error ? err.message : String(err);
      assert.match(message, /entry 0 .*reason/);
      assert.match(message, /entry 1 .*bound/);
      return true;
    },
  );
});

test("validateAllowList accepts entries with both reason and bound", () => {
  const entries = validateAllowList([{ id: "a", location: "b", reason: "y", bound: "z" }]);
  assert.equal(entries.length, 1);
  assert.equal(entries[0].reason, "y");
});

test("loadAllowList throws naming the bad entry when config.json has an invalid allow array", () => {
  const dir = makeTmpDir();
  try {
    const configPath = join(dir, "keysnag.config.json");
    writeFileSync(
      configPath,
      JSON.stringify({ allow: [{ id: "secret.stripe_key", location: "x", reason: "", bound: "" }] }),
    );
    assert.throws(() => loadAllowList(configPath), /reason and bound/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("loadAllowList returns [] when the config file or the allow key is absent", () => {
  const dir = makeTmpDir();
  try {
    assert.deepEqual(loadAllowList(join(dir, "keysnag.config.json")), []);
    writeFileSync(join(dir, "keysnag.config.json"), JSON.stringify({ repoDir: "." }));
    assert.deepEqual(loadAllowList(join(dir, "keysnag.config.json")), []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the `allow` CLI helper appends a valid entry to keysnag.config.json, creating it if missing", () => {
  const dir = makeTmpDir();
  try {
    execFileSync(
      "node",
      [
        CLI,
        "allow",
        "secret.stripe_key",
        "src/app/api/foo/route.ts",
        "--reason",
        "Test fixture key",
        "--bound",
        "no user data",
        "--repo",
        dir,
      ],
      { encoding: "utf8" },
    );

    const configPath = join(dir, "keysnag.config.json");
    assert.ok(existsSync(configPath));
    const config = JSON.parse(readFileSync(configPath, "utf8"));
    assert.equal(config.allow.length, 1);
    assert.equal(config.allow[0].id, "secret.stripe_key");
    assert.equal(config.allow[0].reason, "Test fixture key");
    assert.equal(config.allow[0].bound, "no user data");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the `allow` CLI helper preserves existing config keys and appends to an existing allow array", () => {
  const dir = makeTmpDir();
  try {
    const configPath = join(dir, "keysnag.config.json");
    writeFileSync(
      configPath,
      JSON.stringify({
        siteUrl: "https://example.com",
        allow: [{ id: "existing.id", location: "x", reason: "r", bound: "b" }],
      }),
    );

    execFileSync(
      "node",
      [CLI, "allow", "secret.openai_key", "src/foo.ts", "--reason", "r2", "--bound", "b2", "--repo", dir],
      { encoding: "utf8" },
    );

    const config = JSON.parse(readFileSync(configPath, "utf8"));
    assert.equal(config.siteUrl, "https://example.com");
    assert.equal(config.allow.length, 2);
    assert.equal(config.allow[1].id, "secret.openai_key");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the `allow` CLI helper refuses (exits non-zero, no write) when --reason or --bound is empty", () => {
  const dir = makeTmpDir();
  try {
    assert.throws(() =>
      execFileSync(
        "node",
        [CLI, "allow", "secret.stripe_key", "src/foo.ts", "--reason", "", "--bound", "b", "--repo", dir],
        { encoding: "utf8" },
      ),
    );
    assert.ok(!existsSync(join(dir, "keysnag.config.json")));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
