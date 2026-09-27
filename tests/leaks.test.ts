// tests/leaks.test.ts — the leaks check against throwaway git repos. Paths are built by
// concatenation so this file never contains a literal home-directory path itself.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { execFileSync } from "node:child_process";
import leaks from "../src/checks/leaks.js";

const HOME = "/Us" + "ers/";

function repo(files: Record<string, string>, commitMsg = "initial"): string {
  const dir = mkdtempSync(join(tmpdir(), "keysnag-leaks-"));
  const g = (...a: string[]) => execFileSync("git", ["-C", dir, ...a], { stdio: "pipe" });
  g("init", "-q");
  g("config", "user.email", "test@example.com");
  g("config", "user.name", "Test");
  for (const [p, c] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, p)), { recursive: true });
    writeFileSync(join(dir, p), c);
  }
  g("add", "-A");
  g("commit", "-q", "-m", commitMsg);
  return dir;
}

const run = (repoDir: string, extra: object = {}) => leaks.run({ repoDir, log: () => {}, ...extra });
const ids = (r: Awaited<ReturnType<typeof run>>) => r.findings.map((f) => f.id);

test("flags a real home-directory path, once per username", async () => {
  const dir = repo({ "a.ts": `const p = "${HOME}alice/code/app/x";\nconst q = "${HOME}alice/y/";\n` });
  try {
    const r = await run(dir);
    const hits = r.findings.filter((f) => f.id === "leaks.local_path");
    assert.equal(hits.length, 1);
    assert.match(hits[0].title, /alice/);
    assert.match(hits[0].evidence ?? "", /a\.ts:1, a\.ts:2/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("ignores placeholder and CI usernames", async () => {
  const dir = repo({ "README.md": `${HOME}you/project/\n/home/runner/work/\n/home/user/x/\n` });
  try {
    assert.deepEqual(ids(await run(dir)), []);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("private terms from .keysnag-private hit files, commit messages and history", async () => {
  const dir = repo({ "notes.md": "Tested against Acmecorp staging.\n", ".gitignore": ".keysnag-private\n" }, "Dogfood on Acmecorp");
  try {
    writeFileSync(join(dir, ".keysnag-private"), "# private\nacmecorp\n");
    const r = await run(dir);
    const got = ids(r);
    assert.ok(got.includes("leaks.private_term"), got.join());
    assert.ok(got.includes("leaks.private_term_in_commits"), got.join());
    assert.ok(got.includes("leaks.private_term_in_history"), got.join());
    const f = r.findings.find((x) => x.id === "leaks.private_term")!;
    assert.equal(f.location, "notes.md:1");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("a term cleaned from today's files is still reported in history", async () => {
  const dir = repo({ "a.md": "Built for Acmecorp\n" });
  try {
    writeFileSync(join(dir, "a.md"), "Built for a client\n");
    execFileSync("git", ["-C", dir, "commit", "-qam", "generic"]);
    const got = ids(await run(dir, { privateTerms: ["acmecorp"] }));
    assert.ok(!got.includes("leaks.private_term"), got.join());
    assert.ok(got.includes("leaks.private_term_in_history"), got.join());
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("terms match whole words only", async () => {
  const dir = repo({ "a.md": "the acmecorporation is fine\n" });
  try {
    assert.ok(!ids(await run(dir, { privateTerms: ["acmecorp"] })).includes("leaks.private_term"));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("tracked scaffolding files are flagged, including the private-terms list itself", async () => {
  const dir = repo({ ".vercel/project.json": "{}", ".workflow/LEDGER.md": "x", ".keysnag-private": "acme\n" });
  try {
    const r = await run(dir);
    const locs = r.findings.filter((f) => f.id === "leaks.internal_file").map((f) => f.location).sort();
    assert.deepEqual(locs, [".keysnag-private", ".vercel/project.json", ".workflow/LEDGER.md"]);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("diff mode scans only changed files and skips history", async () => {
  const dir = repo({ "a.md": "Acme\n", "b.md": "clean\n" }, "Acme work");
  try {
    const got = ids(await run(dir, { privateTerms: ["acme"], changedFiles: ["b.md"] }));
    assert.deepEqual(got, []);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("skips cleanly outside a git repo", async () => {
  const dir = mkdtempSync(join(tmpdir(), "keysnag-leaks-nogit-"));
  try {
    const r = await run(dir);
    assert.equal(r.ran, false);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
