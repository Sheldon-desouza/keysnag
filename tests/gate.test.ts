// tests/gate.test.ts — exitCodeForFindings and blockSummary at every --fail-on threshold,
// including "off" (warn-only, never blocks).
import { test } from "node:test";
import assert from "node:assert/strict";
import type { CheckResult, Finding, Severity } from "../src/types.js";
import { exitCodeForFindings, blockSummary } from "../src/gate.js";

function finding(severity: Severity): Finding {
  return {
    id: `test.${severity}`,
    check: "test",
    severity,
    title: `a ${severity} finding`,
    detail: "detail",
    fix: "fix",
  };
}

function resultsWith(...severities: Severity[]): CheckResult[] {
  return [{ check: "test", ran: true, findings: severities.map(finding) }];
}

test("no findings never blocks, at any threshold", () => {
  const results = resultsWith();
  for (const failOn of ["info", "low", "medium", "high", "critical", "off"] as const) {
    assert.equal(exitCodeForFindings(results, failOn), 0);
    assert.equal(blockSummary(results, failOn), "");
  }
});

test("--fail-on off never blocks even with a critical finding", () => {
  const results = resultsWith("critical");
  assert.equal(exitCodeForFindings(results, "off"), 0);
  assert.equal(blockSummary(results, "off"), "");
});

test("--fail-on critical blocks only on critical", () => {
  assert.equal(exitCodeForFindings(resultsWith("high"), "critical"), 0);
  assert.equal(exitCodeForFindings(resultsWith("critical"), "critical"), 2);
});

test("--fail-on high blocks on high and critical, not medium", () => {
  assert.equal(exitCodeForFindings(resultsWith("medium"), "high"), 0);
  assert.equal(exitCodeForFindings(resultsWith("high"), "high"), 2);
  assert.equal(exitCodeForFindings(resultsWith("critical"), "high"), 2);
});

test("--fail-on medium blocks on medium, high, critical, not low", () => {
  assert.equal(exitCodeForFindings(resultsWith("low"), "medium"), 0);
  assert.equal(exitCodeForFindings(resultsWith("medium"), "medium"), 2);
  assert.equal(exitCodeForFindings(resultsWith("high"), "medium"), 2);
});

test("--fail-on low blocks on low and above, not info", () => {
  assert.equal(exitCodeForFindings(resultsWith("info"), "low"), 0);
  assert.equal(exitCodeForFindings(resultsWith("low"), "low"), 2);
});

test("--fail-on info blocks on anything, including info", () => {
  assert.equal(exitCodeForFindings(resultsWith("info"), "info"), 2);
});

test("blockSummary names each severity at or above the threshold, worst first", () => {
  const results = resultsWith("low", "high", "critical", "critical", "medium");
  const summary = blockSummary(results, "medium");
  assert.match(summary, /keysnag blocked:/);
  assert.match(summary, /2 critical/);
  assert.match(summary, /1 high/);
  assert.match(summary, /1 medium/);
  assert.doesNotMatch(summary, /low/);
});

test("blockSummary is empty when nothing crosses the threshold", () => {
  const results = resultsWith("low", "medium");
  assert.equal(blockSummary(results, "high"), "");
});
