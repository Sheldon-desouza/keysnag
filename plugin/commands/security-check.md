---
description: Run keysnag's local security scan on this project and walk through fixing what it finds.
argument-hint: "[optional: repo dir or site URL]"
---

Run keysnag against the current project, then help the user fix what it finds.

1. Run the scan. Prefer `npx keysnag scan` in the project root; if keysnag is built
   locally in this repo instead, run `node dist/cli.js scan`. Pass through any arguments
   in `$ARGUMENTS` as `--repo` or `--url` flags as appropriate (a path looks like `--repo`,
   a URL looks like `--url`).
2. Read the generated `keysnag.report.md` in the project root. Do not guess at findings;
   read the file.
3. Summarize the report for the user: how many checks ran, how many were skipped, and the
   count of findings by severity (critical first).
4. If any checks were skipped, tell the user exactly which `.env` var(s) unlock each one:
   - secrets check needs `KEYSNAG_REPO_DIR` (or run from inside the repo)
   - url probe needs `KEYSNAG_SITE_URL`
   - RLS audit needs `KEYSNAG_PG_URL` (a read-only Postgres connection string)
   - cross-account test needs `KEYSNAG_SUPABASE_URL`, `KEYSNAG_SUPABASE_ANON_KEY`, `KEYSNAG_TOKEN_A`, and `KEYSNAG_TOKEN_B`
   Point them at `.env.example` in the keysnag repo for the exact shape, and remind them
   these values stay local and are never sent anywhere except the URLs they themselves supply.
5. Walk through findings with the user one at a time, critical severity first. For each,
   explain what it is and why it matters in plain language, then ask if they want it fixed
   now. If they say yes, apply the fix described in the finding's `fix` field, matching the
   project's existing code style. Never invent a fix beyond what the finding describes.
6. After fixes are applied, suggest re-running the scan to confirm the finding is gone.

Never print a raw secret value, even one the report shows masked. If a finding's evidence
looks unmasked, treat that as a keysnag bug and flag it instead of relaying the value.
