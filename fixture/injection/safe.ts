// Safe counterpart: parameterised query, no raw eval/exec, a fetch restricted to
// an allowlisted host built without any request-derived value, a path built from
// a validated in-memory lookup (never request input), and a schema-validated
// merge (no raw spread of parsed JSON). None of these should trip any
// injection.* rule.
import { execFile } from "node:child_process";
import path from "node:path";
import { readFile } from "node:fs/promises";

const ALLOWLISTED_HOST = "https://api.partner.example.com";
const KNOWN_REPORTS: Record<string, string> = {
  monthly: "monthly-report.pdf",
  annual: "annual-report.pdf",
};
const REPORTS_DIR = "/srv/reports";

export async function getUser(id: string) {
  // parameterised query: no string concatenation into the SQL text
  return db.query("SELECT * FROM users WHERE id = $1", [id]);
}

export async function fetchPartnerStatus() {
  // fixed, allowlisted host, never built from request input
  const res = await fetch(`${ALLOWLISTED_HOST}/status`);
  return res.json();
}

export async function readKnownReport(key: string) {
  // key is looked up in a fixed in-memory map, never joined from raw input
  const name = KNOWN_REPORTS[key] ?? KNOWN_REPORTS.monthly;
  const filePath = path.join(REPORTS_DIR, name);
  return readFile(filePath);
}

export function runBackup() {
  // execFile with an argument array, no shell, nothing interpolated
  execFile("tar", ["-czf", "/tmp/backup.tgz", "/srv/data"]);
}

interface Settings {
  theme: string;
  notifications: boolean;
}

export function applySettings(input: unknown): Settings {
  const parsed = SettingsSchema.parse(input);
  return { theme: parsed.theme, notifications: parsed.notifications };
}

declare const db: { query: (sql: string, params: unknown[]) => Promise<unknown> };
declare const SettingsSchema: { parse: (v: unknown) => Settings };
