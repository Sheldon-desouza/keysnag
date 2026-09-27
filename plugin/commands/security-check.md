---
description: Run keysnag's local security scan on this project and walk through fixing what it finds.
argument-hint: "[optional: repo dir or site URL]"
---

Run keysnag against the current project, then help the user fix what it finds.
This is the gate: a blocking (critical) finding on `git commit`/`git push` also
triggers this same scan automatically via keysnag's Claude Code hook, so the
workflow below is the same one Claude follows when woken up by that hook.

1. Run the scan. Prefer `npx keysnag scan` in the project root; if keysnag is built
   locally in this repo instead, run `node dist/cli.js scan`. Pass through any arguments
   in `$ARGUMENTS` as `--repo` or `--url` flags as appropriate (a path looks like `--repo`,
   a URL looks like `--url`).
2. Read the generated `keysnag.report.md` in the project root. Do not guess at findings;
   read the file.
3. Summarize the report for the user: how many of the 13 checks ran, how many were
   skipped, and the count of findings by severity (critical first).
4. If any checks were skipped, tell the user exactly which `.env` var(s) unlock each one:
   - `secrets`, `config`, `authz`, `injection`, `payments`, `backdoor`, `ai-endpoints`, `leaks` run
     with no inputs beyond the repo itself (`leaks` also reads a gitignored `.keysnag-private`
     list of names that must not go public)
   - `deps` needs a lockfile (`package-lock.json`/`pnpm-lock.yaml`/`yarn.lock`)
   - `urlprobe` needs `KEYSNAG_SITE_URL`
   - `rls` needs `KEYSNAG_PG_URL` (a read-only Postgres connection string)
   - `storage`'s bucket/policy audit needs `KEYSNAG_PG_URL`; its edge-function and cron
     checks are repo-static and always run
   - `twoaccount` needs `KEYSNAG_SUPABASE_URL`, `KEYSNAG_SUPABASE_ANON_KEY`,
     `KEYSNAG_TOKEN_A`, and `KEYSNAG_TOKEN_B`
   Point them at `.env.example` in the keysnag repo for the exact shape, and remind them
   these values stay local and are never sent anywhere except the URLs they themselves
   supply (plus one opt-out exception: `deps` calls OSV.dev for CVE lookups unless
   `--no-osv` or `KEYSNAG_ALLOW_OSV=false` is set).
5. Walk through findings with the user one at a time, critical severity first. For each,
   explain what it is and why it matters in plain language, then ask if they want it fixed
   now. If they say yes, apply the fix described in the finding's `fix` field, matching the
   project's existing code style. Never invent a fix beyond what the finding describes.
6. If the user decides a finding is a genuine, reviewed exception (not a bug in the
   check), use the allow-list instead of ignoring it: run
   `keysnag allow <finding-id> <location> --reason "..." --bound "..."`. Both `--reason`
   (why it's acceptable) and `--bound` (the compensating control, e.g. a rate limit or an
   explicit "no user data") are mandatory; keysnag refuses to run at all if either is
   missing on any entry. An allowed finding still shows up in the report as `info`, it
   just never blocks a push.
7. After fixes (or allow-list entries) are applied, suggest re-running the scan to
   confirm the finding is gone or downgraded.

Never print a raw secret value, even one the report shows masked. If a finding's evidence
looks unmasked, treat that as a keysnag bug and flag it instead of relaying the value.
