# keysnag for Claude Code

Cybersecurity for AI founders and vibe coders. A pre-push security gate for apps built with Claude Code, Cursor, Lovable and Bolt.

## What this plugin does

- **Auto-runs on every `git commit` and `git push`** you make from inside Claude Code. If keysnag finds a blocking (critical) finding, the findings are handed straight back to Claude so it fixes them before continuing.
- **`/security-check`**: runs the full scan on demand and walks you through the findings, critical first, with a fix for each.
- **A skill** that tells Claude when a security check is warranted (before a launch, after touching auth, payments, database access, API keys or user data) and how to read the report.

The scan itself is [keysnag](https://github.com/Sheldon-desouza/keysnag) (MIT, on npm). Twelve deterministic checks: secrets in the repo and the shipped JS bundle, insecure config, routes with no auth check, client-supplied identity, injection (SQL, XSS, eval, shell, SSRF, traversal), Stripe webhook and pricing flaws, backdoors, AI-endpoint abuse, known CVEs in your lockfile, Supabase RLS and storage policies, an exposed-URL probe, and a two-account cross-user access test.

## How it runs

The hook resolves the keysnag CLI in this order: `KEYSNAG_CLI` if set, the repo's own `dist/cli.js` when the plugin is used from a keysnag checkout, otherwise `npx -y keysnag@latest`. The first run may take a few seconds while npm fetches the package.

## Privacy

No telemetry. keysnag talks only to the site, Supabase project or database you configure in a local `.env`, plus one optional call to OSV.dev for CVE data (`--no-osv` disables it). Secrets are always masked in reports.

## Not a pentest

keysnag catches the defect classes behind most real breaches of AI-built apps. It is not a substitute for a professional security review, and it never claims your app is unhackable.

Full documentation and threat model: https://github.com/Sheldon-desouza/keysnag
