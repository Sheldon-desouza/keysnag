---
name: keysnag
description: No-telemetry pre-push security gate for AI-built Next.js + Supabase apps, 12 checks covering leaked secrets, misconfiguration, broken access control, injection, payments/webhooks, backdoors, AI-endpoint abuse, dependency CVEs, storage/RLS, exposed URLs, and cross-account data leaks. Use when the user asks things like "is my app secure", "check before launch", "audit my supabase app", "did the AI leak my keys", or before shipping a vibe-coded project to real users.
---

# keysnag

keysnag runs 12 checks against a project and nothing else: it never phones
home, and the only network calls it makes are to a site URL, Supabase URL, or
Postgres URL the user supplies themselves, plus one opt-out exception: `deps`
looks up known CVEs via OSV.dev unless `--no-osv` / `KEYSNAG_ALLOW_OSV=false`
is set. Once the Claude Code plugin is installed, it also auto-runs on every
`git commit` and `git push` in this project, and feeds any blocking (critical)
finding straight back to Claude to fix before continuing.

## When to run this

Run it when the user:
- asks "is my app secure" / "am I safe to launch" / "check before launch"
- asks to audit a Supabase-backed app, or asks about RLS specifically
- mentions AI-generated or "vibe-coded" code they haven't security-reviewed
- is about to ship, deploy, or take real signups for the first time
- has just committed or pushed and the auto-run hook woke you up with a
  blocking finding

## How to run it

- CLI: `npx keysnag scan --repo <dir> --url <site url>` (flags optional; each
  missing input just skips the checks that need it). `keysnag install` adds a
  real git pre-push hook (works the same in Cursor, VS Code, a bare terminal,
  or CI); `keysnag install --pre-commit` adds a lighter secrets-only
  pre-commit hook; `keysnag uninstall` removes them.
- MCP: call `run_security_check` for the full report, or `check_<name>` for a
  single check (one per check name below).
- Slash command: `/security-check` runs the scan and walks the user through
  fixes interactively (see `commands/security-check.md`).

## The 12 checks

Repo-static (no inputs beyond the code itself, always run):
- **secrets** — API keys, service_role JWTs, and other credentials hardcoded
  or committed where they'll reach a client bundle.
- **config** — public env secrets, TLS verification off, prod source maps,
  permissive CORS, insecure cookies, weak randomness/hashing, hardcoded JWT
  secrets, debug flags left on.
- **authz** — routes/server actions that touch the database with no auth
  check, client-supplied identity used in a query (IDOR), `/admin` routes
  with no role check.
- **injection** — SQL concatenation, dangerous HTML sinks, eval/exec, SSRF,
  path traversal, prototype pollution.
- **payments** — unverified Stripe webhooks, client-priced charges, missing
  idempotency keys.
- **backdoor** — obfuscated eval chains, hardcoded bypasses, auth-skip flags,
  `process.env` dumps, unexpected outbound hosts, prompt-injection artifacts.
- **ai-endpoints** — LLM calls from the browser, AI routes with no auth or
  spend bound, raw-input prompts, unsanitised LLM output rendered as HTML.
- **deps** — known CVEs (via OSV.dev) in your lockfile-pinned versions,
  unpinned deps, install scripts, lockfile drift. Needs a lockfile.

Live site / database / accounts:
- **urlprobe** — hits the live site and looks for exposed debug routes,
  leaked config, or unauthenticated admin surfaces. Needs `KEYSNAG_SITE_URL`.
- **rls** — connects with a read-only Postgres role and checks Supabase
  tables for missing or misconfigured Row Level Security. Needs
  `KEYSNAG_PG_URL`.
- **storage** — public storage buckets and wide-open storage policies (needs
  `KEYSNAG_PG_URL`); edge functions with JWT verification off and cron routes
  with no shared secret (repo-static, always runs).
- **twoaccount** — signs in as two real users (via their JWTs) and checks
  whether user A can read or write user B's data. Needs `KEYSNAG_SUPABASE_URL`,
  `KEYSNAG_SUPABASE_ANON_KEY`, `KEYSNAG_TOKEN_A`, `KEYSNAG_TOKEN_B`.

## Accepting a finding instead of fixing it

If a finding is a real match on code the user has reviewed and genuinely
accepts (a public tool by design, a webhook verified a different way), use
`keysnag allow <finding-id> <location> --reason "..." --bound "..."` instead
of ignoring it. Both flags are mandatory: `reason` says why it's acceptable,
`bound` says what actually stops it being abused (a rate limit, a plan gate,
an auth check, or an explicit "no user data"). keysnag refuses to run at all
if any allow-list entry is missing either. An allowed finding still appears
in the report as `info`, prefixed `[allowed]`; it just never blocks a push.

## Reading the output

The report groups findings critical first, then high, medium, low, info, and
lists any skipped checks with the plain-English reason (always a missing
input, never a crash). Secret values are always masked (first 4 + last 4
chars); never relay an unmasked value even if one somehow appears. The
"agent tasks" block at the end is meant to be acted on directly: one bullet
per finding with severity, location, and a concrete fix.

Findings are not proof of a breach, they're proof of an opening. Treat
critical and high findings (leaked service-role keys, tables with no RLS, one
user reading another's data) as launch blockers; medium/low are hardening.
