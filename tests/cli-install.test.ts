// tests/cli-install.test.ts — `keysnag install`/`uninstall` against a real temp git repo,
// run through the built CLI (dist/cli.js) since this is process/filesystem behavior, not a
// pure function. Covers: hook written + executable, chaining an existing hook, idempotent
// re-install, and clean uninstall that restores the chained hook.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  mkdtempSync,
  rmSync,
  writeFileSync,
  readFileSync,
  existsSync,
  chmodSync,
  statSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const CLI = resolve(process.cwd(), "dist/cli.js");

function makeTmpRepo(): string {
  const dir = mkdtempSync(join(tmpdir(), "keysnag-install-test-"));
  execFileSync("git", ["init", "-q"], { cwd: dir });
  return dir;
}

function isExecutable(path: string): boolean {
  const mode = statSync(path).mode;
  return (mode & 0o100) !== 0;
}

test("install writes an executable pre-push hook that runs keysnag", () => {
  const repo = makeTmpRepo();
  try {
    execFileSync("node", [CLI, "install", "--repo", repo], { encoding: "utf8" });

    const hookPath = join(repo, ".git", "hooks", "pre-push");
    assert.ok(existsSync(hookPath), "pre-push hook should exist");
    assert.ok(isExecutable(hookPath), "pre-push hook should be executable");
    assert.match(readFileSync(hookPath, "utf8"), /keysnag/);
  } finally {
    rmSync(repo, { recursive: true, force: true });
  }
});

test("install is idempotent: running it twice does not double-chain or duplicate content", () => {
  const repo = makeTmpRepo();
  try {
    execFileSync("node", [CLI, "install", "--repo", repo], { encoding: "utf8" });
    const first = readFileSync(join(repo, ".git", "hooks", "pre-push"), "utf8");

    execFileSync("node", [CLI, "install", "--repo", repo], { encoding: "utf8" });
    const second = readFileSync(join(repo, ".git", "hooks", "pre-push"), "utf8");

    assert.equal(first, second);
    assert.ok(
      !existsSync(join(repo, ".git", "hooks", "pre-push.keysnag-prev")),
      "no chained backup should appear when there was nothing to chain",
    );
  } finally {
    rmSync(repo, { recursive: true, force: true });
  }
});

test("install chains a pre-existing pre-push hook, and uninstall restores it", () => {
  const repo = makeTmpRepo();
  try {
    const hooksDir = join(repo, ".git", "hooks");
    const existingHookPath = join(hooksDir, "pre-push");
    const dummyHook = "#!/bin/sh\necho dummy-existing-hook\nexit 0\n";
    writeFileSync(existingHookPath, dummyHook, "utf8");
    chmodSync(existingHookPath, 0o755);

    execFileSync("node", [CLI, "install", "--repo", repo], { encoding: "utf8" });

    const prevPath = join(hooksDir, "pre-push.keysnag-prev");
    assert.ok(existsSync(prevPath), "the pre-existing hook should be renamed, not lost");
    assert.equal(readFileSync(prevPath, "utf8"), dummyHook);

    const chainedContent = readFileSync(existingHookPath, "utf8");
    assert.match(chainedContent, /pre-push\.keysnag-prev/);
    assert.match(chainedContent, /keysnag/);

    execFileSync("node", [CLI, "uninstall", "--repo", repo], { encoding: "utf8" });

    assert.ok(!existsSync(prevPath), "the backup should be consumed on uninstall");
    assert.ok(existsSync(existingHookPath), "the original hook should be restored");
    assert.equal(readFileSync(existingHookPath, "utf8"), dummyHook);
  } finally {
    rmSync(repo, { recursive: true, force: true });
  }
});

test("uninstall removes a keysnag hook with nothing to chain", () => {
  const repo = makeTmpRepo();
  try {
    execFileSync("node", [CLI, "install", "--repo", repo], { encoding: "utf8" });
    const hookPath = join(repo, ".git", "hooks", "pre-push");
    assert.ok(existsSync(hookPath));

    execFileSync("node", [CLI, "uninstall", "--repo", repo], { encoding: "utf8" });
    assert.ok(!existsSync(hookPath), "pre-push hook should be gone after uninstall");
  } finally {
    rmSync(repo, { recursive: true, force: true });
  }
});

test("install --pre-commit also writes a pre-commit hook", () => {
  const repo = makeTmpRepo();
  try {
    execFileSync("node", [CLI, "install", "--pre-commit", "--repo", repo], { encoding: "utf8" });

    const hookPath = join(repo, ".git", "hooks", "pre-commit");
    assert.ok(existsSync(hookPath));
    assert.ok(isExecutable(hookPath));
    assert.match(readFileSync(hookPath, "utf8"), /keysnag/);

    execFileSync("node", [CLI, "uninstall", "--repo", repo], { encoding: "utf8" });
    assert.ok(!existsSync(hookPath));
  } finally {
    rmSync(repo, { recursive: true, force: true });
  }
});
