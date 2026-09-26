// tests/plugin-gate.test.ts — the Claude Code plugin hook (plugin/hooks/gate.mjs), run against a
// stub CLI via KEYSNAG_CLI, per the asyncRewake protocol (security-guidance's
// hooks/security_reminder_hook.py:1489-1493): exit 2 wakes Claude with the findings, exit 0 stays
// quiet, and a missing/broken CLI never blocks.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, chmodSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const GATE = resolve(process.cwd(), "plugin/hooks/gate.mjs");

function makeTmpDir(): string {
  return mkdtempSync(join(tmpdir(), "keysnag-gate-test-"));
}

function writeStub(dir: string, name: string, script: string): string {
  const path = join(dir, name);
  writeFileSync(path, script, "utf8");
  chmodSync(path, 0o755);
  return path;
}

function runGate(stubPath: string, cwd: string) {
  return spawnSync("node", [GATE], {
    cwd,
    encoding: "utf8",
    env: { ...process.env, KEYSNAG_CLI: stubPath },
  });
}

test("gate.mjs exits 2 when the CLI reports a critical finding, waking Claude via asyncRewake", () => {
  const dir = makeTmpDir();
  try {
    const stub = writeStub(dir, "stub-critical.sh", "#!/bin/sh\necho '1 critical'\nexit 0\n");
    const result = runGate(stub, dir);
    assert.equal(result.status, 2);
    assert.match(result.stdout, /keysnag security gate/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("gate.mjs exits 0 when the CLI reports no findings", () => {
  const dir = makeTmpDir();
  try {
    const stub = writeStub(dir, "stub-clean.sh", "#!/bin/sh\necho 'no findings'\nexit 0\n");
    const result = runGate(stub, dir);
    assert.equal(result.status, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("gate.mjs exits 0 (never blocks) when the CLI is missing", () => {
  const dir = makeTmpDir();
  try {
    const missing = join(dir, "does-not-exist.sh");
    const result = runGate(missing, dir);
    assert.equal(result.status, 0);
    assert.match(result.stdout, /keysnag could not run/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("gate.mjs never mirrors the child's own exit code blindly: a stub that exits 2 but reports no critical count stays 0", () => {
  const dir = makeTmpDir();
  try {
    const stub = writeStub(dir, "stub-exit2-clean.sh", "#!/bin/sh\necho 'no findings'\nexit 2\n");
    const result = runGate(stub, dir);
    assert.equal(result.status, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
