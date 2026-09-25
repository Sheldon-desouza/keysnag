// tests/config.test.ts — precedence CLI > env > keysnag.config.json, and .env parsing.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadContext } from "../src/config.js";

function makeTmpDir(): string {
  return mkdtempSync(join(tmpdir(), "keysnag-config-test-"));
}

test("config.json alone sets a field", () => {
  const dir = makeTmpDir();
  try {
    writeFileSync(
      join(dir, "keysnag.config.json"),
      JSON.stringify({ siteUrl: "https://from-config.example" }),
    );
    const ctx = loadContext({ cwd: dir });
    assert.equal(ctx.siteUrl, "https://from-config.example");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("env var overrides keysnag.config.json", () => {
  const dir = makeTmpDir();
  try {
    writeFileSync(
      join(dir, "keysnag.config.json"),
      JSON.stringify({ siteUrl: "https://from-config.example" }),
    );
    const original = process.env.KEYSNAG_SITE_URL;
    process.env.KEYSNAG_SITE_URL = "https://from-env.example";
    try {
      const ctx = loadContext({ cwd: dir });
      assert.equal(ctx.siteUrl, "https://from-env.example");
    } finally {
      if (original === undefined) delete process.env.KEYSNAG_SITE_URL;
      else process.env.KEYSNAG_SITE_URL = original;
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("CLI override beats both env var and config file", () => {
  const dir = makeTmpDir();
  try {
    writeFileSync(
      join(dir, "keysnag.config.json"),
      JSON.stringify({ siteUrl: "https://from-config.example" }),
    );
    const original = process.env.KEYSNAG_SITE_URL;
    process.env.KEYSNAG_SITE_URL = "https://from-env.example";
    try {
      const ctx = loadContext({ cwd: dir, siteUrl: "https://from-cli.example" });
      assert.equal(ctx.siteUrl, "https://from-cli.example");
    } finally {
      if (original === undefined) delete process.env.KEYSNAG_SITE_URL;
      else process.env.KEYSNAG_SITE_URL = original;
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test(".env file is parsed and fills a field when no real env var is set", () => {
  const dir = makeTmpDir();
  try {
    writeFileSync(
      join(dir, ".env"),
      [
        "# a comment, ignored",
        "",
        'KEYSNAG_PG_URL="postgres://readonly:pw@localhost:5432/postgres"',
        "KEYSNAG_SUPABASE_URL=https://from-dotenv.example",
      ].join("\n"),
    );
    const ctx = loadContext({ cwd: dir });
    assert.equal(ctx.pgUrl, "postgres://readonly:pw@localhost:5432/postgres");
    assert.equal(ctx.supabaseUrl, "https://from-dotenv.example");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a real env var is not overwritten by a conflicting .env value", () => {
  const dir = makeTmpDir();
  try {
    writeFileSync(join(dir, ".env"), "KEYSNAG_SUPABASE_URL=https://from-dotenv.example");
    const original = process.env.KEYSNAG_SUPABASE_URL;
    process.env.KEYSNAG_SUPABASE_URL = "https://from-real-env.example";
    try {
      const ctx = loadContext({ cwd: dir });
      assert.equal(ctx.supabaseUrl, "https://from-real-env.example");
    } finally {
      if (original === undefined) delete process.env.KEYSNAG_SUPABASE_URL;
      else process.env.KEYSNAG_SUPABASE_URL = original;
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
