// payments: repo-static checks for Stripe payment/webhook flaws (T5 in the threat model):
// an unverified webhook, a charge priced from client input, and missing idempotency keys.
// Reuses the getScanFiles-style helper and finding shape from secrets.ts.
import { readFile, stat, readdir } from "node:fs/promises";
import { join, relative, extname } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { Check, CheckContext, CheckResult, Finding } from "../types.js";

const pexec = promisify(execFile);

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", ".next", "build", ".claude", ".vercel", "coverage", ".turbo", "out"]);
const SKIP_EXTS = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".woff", ".woff2",
  ".ttf", ".eot", ".pdf", ".zip", ".gz", ".tgz", ".mp4", ".mov", ".mp3",
  ".wasm", ".node", ".lock", ".map",
]);
const MAX_FILE_BYTES = 2 * 1024 * 1024;

async function walkRepo(root: string): Promise<string[]> {
  const results: string[] = [];
  async function walk(dir: string) {
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        await walk(join(dir, entry.name));
      } else if (entry.isFile()) {
        if (SKIP_EXTS.has(extname(entry.name))) continue;
        results.push(join(dir, entry.name));
      }
    }
  }
  await walk(root);
  return results;
}

async function getScanFiles(repoDir: string, changedFiles: string[] | undefined): Promise<string[]> {
  if (changedFiles && changedFiles.length > 0) {
    return changedFiles.map((f) => join(repoDir, f));
  }
  try {
    const { stdout } = await pexec(
      "git",
      ["-C", repoDir, "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
      { maxBuffer: 128 * 1024 * 1024 },
    );
    const rel = stdout.split("\u0000").filter(Boolean);
    if (rel.length === 0) return await walkRepo(repoDir);
    return rel.filter((r) => !SKIP_EXTS.has(extname(r))).map((r) => join(repoDir, r));
  } catch {
    return await walkRepo(repoDir);
  }
}

/** Conventional unit-test/mock dirs and filenames of the *scanned* repo, not keysnag's own fixtures. */
function isTestFile(relPath: string): boolean {
  const norm = relPath.replace(/\\/g, "/");
  if (/(^|\/)(__tests__|__mocks__)\//.test(norm)) return true;
  if (/\.(test|spec)\.[jt]sx?$/.test(norm)) return true;
  return false;
}

const CONSTRUCT_EVENT = /constructEvent(Async)?\s*\(/;
const WEBHOOK_SIGNAL = /webhook/i;
const STRIPE_EVENT_SIGNAL = /stripe-signature|stripe\.webhooks|event\.type\s*===?\s*['"]/i;

function rule_webhookUnverified(relPath: string, text: string, findings: Finding[]) {
  const norm = relPath.replace(/\\/g, "/");
  const isCandidate = WEBHOOK_SIGNAL.test(norm) || STRIPE_EVENT_SIGNAL.test(text);
  if (!isCandidate) return;
  if (CONSTRUCT_EVENT.test(text)) return; // signature is verified somewhere in the file

  const lines = text.split("\n");
  const handlerLine = lines.findIndex((l) => /export\s+(async\s+)?function\s+POST/.test(l));
  const line = handlerLine >= 0 ? handlerLine + 1 : 1;
  findings.push({
    id: "payments.webhook_unverified",
    check: "payments",
    severity: "critical",
    title: "Stripe webhook route does not verify the signature",
    detail: "This route looks like a Stripe webhook handler (its path mentions webhook, or it reads Stripe event data) but never calls stripe.webhooks.constructEvent/constructEventAsync. Without signature verification, anyone can POST a forged event and trigger whatever the handler does (grant access, mark an order paid, etc.).",
    location: `${relPath}:${line}`,
    fix: "Verify every incoming event with stripe.webhooks.constructEvent(rawBody, request.headers.get('stripe-signature'), process.env.STRIPE_WEBHOOK_SECRET) before acting on it, using the raw request body (not a parsed JSON body).",
  });
}

const CHARGE_CALL = /\.(checkout\.sessions|paymentIntents|charges|invoiceItems)\.create\s*\(/g;
const PRICE_FIELDS = "amount|price|unit_amount|currency|total";
const REQUEST_DERIVED_PRICE = new RegExp(
  `\\b(?:req\\.body|request\\.body|body)\\.(?:${PRICE_FIELDS})\\b` +
    `|searchParams\\.get\\(\\s*['"](?:${PRICE_FIELDS})['"]\\s*\\)` +
    `|\\bparams\\.(?:${PRICE_FIELDS})\\b` +
    `|const\\s*{[^}]*\\b(?:${PRICE_FIELDS})\\b[^}]*}\\s*=\\s*(?:await\\s+)?(?:req|request)\\.json\\(\\)` +
    `|const\\s*{[^}]*\\b(?:${PRICE_FIELDS})\\b[^}]*}\\s*=\\s*body\\b`,
  "i",
);
const IDEMPOTENCY_KEY = /idempotencyKey\s*:/;

function rule_chargeCalls(relPath: string, text: string, findings: Finding[]) {
  const lines = text.split("\n");
  CHARGE_CALL.lastIndex = 0;
  for (const m of text.matchAll(CHARGE_CALL)) {
    const method = m[1];
    const before = text.slice(0, m.index ?? 0);
    const line = before.split("\n").length;

    const start = Math.max(0, line - 1 - 15);
    const end = Math.min(lines.length, line - 1 + 16);
    const windowText = lines.slice(start, end).join("\n");

    if (REQUEST_DERIVED_PRICE.test(windowText)) {
      findings.push({
        id: "payments.client_priced_charge",
        check: "payments",
        severity: "critical",
        title: `charge/session amount taken from the request (${method}.create)`,
        detail: `A price-related field (amount/price/unit_amount/currency/total) is read from the incoming request and used near this ${method}.create call. A client can send any amount it likes and pay whatever it chooses, or nothing at all.`,
        location: `${relPath}:${line}`,
        fix: "Look up the price/amount server-side (from your own product catalogue or a Stripe Price id) instead of trusting any amount, price, unit_amount, currency, or total sent by the client.",
      });
    }

    if (
      (method === "paymentIntents" || method === "charges") &&
      !IDEMPOTENCY_KEY.test(windowText)
    ) {
      findings.push({
        id: "payments.no_idempotency",
        check: "payments",
        severity: "low",
        title: `${method}.create called without an idempotency key`,
        detail: `Without idempotencyKey, a retried request (a network blip, a double click, a webhook redelivery) can create a duplicate charge for the same purchase.`,
        location: `${relPath}:${line}`,
        fix: `Pass a stable idempotencyKey (e.g. derived from the order id) as the second argument's options: stripe.${method}.create({ ... }, { idempotencyKey: orderId }).`,
      });
    }
  }
}

const paymentsCheck: Check = {
  name: "payments",
  description: "Static checks for Stripe payment and webhook flaws: unverified webhooks, client-priced charges, and missing idempotency keys.",
  requires: [],
  async run(ctx: CheckContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const repoDir = ctx.repoDir ?? ".";
    const files = await getScanFiles(repoDir, ctx.changedFiles);

    for (const filePath of files) {
      let info;
      try {
        info = await stat(filePath);
      } catch {
        continue;
      }
      if (!info.isFile() || info.size > MAX_FILE_BYTES) continue;

      const relPath = relative(repoDir, filePath);
      if (isTestFile(relPath)) continue;

      let text: string;
      try {
        text = await readFile(filePath, "utf8");
      } catch {
        continue;
      }
      if (text.includes("\u0000")) continue;

      rule_webhookUnverified(relPath, text, findings);
      rule_chargeCalls(relPath, text, findings);
    }

    ctx.log(`payments: scanned ${files.length} file(s), found ${findings.length} finding(s)`);
    return { check: "payments", ran: true, findings };
  },
};

export default paymentsCheck;
