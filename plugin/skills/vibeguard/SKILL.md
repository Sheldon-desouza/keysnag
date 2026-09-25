---
name: vibeguard
description: Local, no-telemetry security checks for AI-built Next.js + Supabase apps (leaked secrets, exposed URLs, missing RLS, cross-account data leaks). Use when the user asks things like "is my app secure", "check before launch", "audit my supabase app", "did the AI leak my keys", or before shipping a vibe-coded project to real users.
---

# vibeguard

vibeguard runs four checks against a project and nothing else: it never phones
home, and the only network calls it makes are to a site URL, Supabase URL, or
Postgres URL the user supplies themselves.

## When to run this

Run it when the user:
- asks "is my app secure" / "am I safe to launch" / "check before launch"
- asks to audit a Supabase-backed app, or asks about RLS specifically
- mentions AI-generated or "vibe-coded" code they haven't security-reviewed
- is about to ship, deploy, or take real signups for the first time

## How to run it

- CLI: `npx vibeguard scan --repo <dir> --url <site url>` (flags optional; each
  missing input just skips the checks that need it).
- MCP: call `run_security_check` for the full report, or `check_<name>` for a
  single check (`check_secrets`, `check_urlprobe`, `check_rls`,
  `check_twoaccount`).
- Slash command: `/security-check` runs the scan and walks the user through
  fixes interactively (see `commands/security-check.md`).

## The four checks

- **secrets** — scans the repo for secrets that ended up somewhere they'll
  reach a client bundle (service-role keys, DB passwords, etc). Needs
  `VG_REPO_DIR` (or run from inside the repo).
- **urlprobe** — hits the live site URL and looks for exposed debug routes,
  leaked config, or unauthenticated admin surfaces. Needs `VG_SITE_URL`.
- **rls** — connects with a read-only Postgres role and checks Supabase tables
  for missing or misconfigured Row Level Security. Needs `VG_PG_URL`.
- **twoaccount** — signs in as two real users (via their JWTs) and checks
  whether user A can read or write user B's data. Needs `VG_SUPABASE_URL`,
  `VG_SUPABASE_ANON_KEY`, `VG_TOKEN_A`, `VG_TOKEN_B`.

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
