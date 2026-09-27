<p align="center">
  <img src="https://raw.githubusercontent.com/Sheldon-desouza/keysnag/main/docs/assets/hero.svg" alt="keysnag: cybersecurity for AI founders and vibe coders. The pre-push security gate for apps built with Claude Code, Cursor, Lovable and Bolt." width="100%">
</p>

<p align="center">
  <a href="LICENSE"><img alt="MIT licence" src="https://img.shields.io/badge/licence-MIT-a3e635?style=flat-square"></a>
  <img alt="12 security checks" src="https://img.shields.io/badge/checks-12-22d3ee?style=flat-square">
  <img alt="Runs offline" src="https://img.shields.io/badge/runs-offline-0ea5e9?style=flat-square">
  <img alt="Node 22" src="https://img.shields.io/badge/node-22%2B-3c873a?style=flat-square">
  <img alt="Works with Claude Code, Cursor, Codex, Lovable, Bolt" src="https://img.shields.io/badge/works%20with-Claude%20Code%20%C2%B7%20Cursor%20%C2%B7%20Codex%20%C2%B7%20Lovable%20%C2%B7%20Bolt-f472b6?style=flat-square">
</p>

<h1 align="center">Stop your AI-built app leaking before it ships</h1>

<p align="center"><strong>keysnag</strong> is a free, open-source security gate that runs <em>before</em> your code reaches <code>main</code> and your live site. It catches the exact mistakes AI coding agents make (leaked keys, missing Supabase RLS, one user reading another user's data, unverified Stripe webhooks, known CVEs, backdoors) and blocks the push if any of them is critical. Twelve checks, under ten seconds, nothing leaves your machine.</p>

<p align="center">
  <a href="https://keysnag.dev">keysnag.dev</a> ·
  <a href="#install-in-60-seconds">Install in 60 seconds</a> ·
  <a href="#what-it-checks">What it checks</a> ·
  <a href="#why-you-can-trust-it">Why you can trust it</a> ·
  <a href="#install-in-claude-code">Claude Code plugin</a> ·
  <a href="#install-as-an-mcp-server">MCP server</a> ·
  <a href="docs/THREAT-MODEL-AND-CHECKS.md">Threat model</a>
</p>

---

## The problem

You built something real with Claude Code, Cursor, Lovable or Bolt. It works. Now you are about to put it in front of real users, and you have no security team.

This is how apps like yours actually get breached, in order of how often it happens:

| What goes wrong | What it costs |
|---|---|
| A `service_role` key, Stripe secret or LLM key ends up in a committed `.env` or the JS bundle | Full read/write of your database, forged charges, an API bill you did not agree to |
| Row Level Security is off, or a policy says `USING (true)`, or it checks "logged in" but not "owns this row" | Any signed-up user reads or edits everyone's data by changing an id |
| A route trusts a `userId` from the request body, or an `/admin` page is only hidden in the UI | Same thing, one `curl` away |
| A Stripe webhook never verifies its signature, or the price comes from the client | Free product |
| A dependency pinned to whatever version the model remembered | A CVE you never wrote |
| No rate limit on the LLM route you shipped | One user loops it and drains your credits |

In 2025 one scan of 1,645 apps built with a single AI builder found 170 with wide-open databases. Independent testing puts the share of AI-generated code with an OWASP Top 10 flaw at around 45%. The r/vibecoding thread with the most upvotes this year is a list of the same seven mistakes found in "every single" AI-built app a consultancy cleaned up.

Every one of those is a known, catchable defect class. keysnag catches them before the push.

## How it works

<p align="center">
  <img src="https://raw.githubusercontent.com/Sheldon-desouza/keysnag/main/docs/assets/how-it-works.svg" alt="How keysnag works: your agent writes code, you push, keysnag runs 12 checks, a critical finding blocks the push and is fed back to the agent to fix, clean code reaches main." width="100%">
</p>

1. You (or your agent) run `git push`.
2. keysnag's pre-push hook scans the tracked tree and, if you gave it a URL or database, the live site and the schema.
3. A **critical** finding (a leaked secret, RLS off on user data, a proven cross-account read) **blocks the push** with the file, the line, and a fix written so a coding agent can apply it. Inside Claude Code, the plugin hook wakes Claude with the findings so it fixes them before continuing.
4. Everything else is saved to `keysnag.report.md` as advisories for you to triage when you choose. Clean code goes through untouched.

It is a plain git hook, so it behaves identically whether you push from Cursor, VS Code, a terminal, or CI.

## Install in 60 seconds

No install step. Run it straight from npm inside your project:

```bash
# one-off scan of the current repo
npx keysnag scan

# add the pre-push gate (chains any hook you already have, gitignores its reports)
npx keysnag install
```

Prefer a local checkout? `git clone https://github.com/Sheldon-desouza/keysnag.git && cd keysnag && npm install && npm run build`, then `node dist/cli.js scan --repo /path/to/your/app`.

Optional: point it at your live site and database to unlock the live checks. Copy `.env.example` to `.env` in the keysnag folder and fill in what you have:

```bash
KEYSNAG_SITE_URL=https://your-app.vercel.app           # live-URL probes
KEYSNAG_PG_URL=postgres://readonly:...                  # RLS + storage audit (read-only role)
KEYSNAG_SUPABASE_URL=https://xxxx.supabase.co          # cross-account test
KEYSNAG_SUPABASE_ANON_KEY=eyJ...
KEYSNAG_TOKEN_A=eyJ...                                  # two test users' JWTs
KEYSNAG_TOKEN_B=eyJ...
```

Any check whose inputs are missing is skipped and the report tells you exactly which variable would turn it on. Nothing is ever a false failure.

## What it checks

<p align="center">
  <img src="https://raw.githubusercontent.com/Sheldon-desouza/keysnag/main/docs/assets/checks.svg" alt="The 12 keysnag checks at a glance: secrets, config, authz, injection, payments, backdoor, ai-endpoints, deps, urlprobe, rls, storage, twoaccount." width="100%">
</p>

12 checks, grouped by what they need. "Blocks a push?" reflects the default gate (`--fail-on critical`): only critical findings stop a push; everything else is reported and left for you.

### Repo / static (no inputs beyond the code itself)

| Check | What it catches | Blocks a push? |
|---|---|---|
| `secrets` | API keys, `service_role` JWTs and other credentials hardcoded or committed where they reach a client bundle. Git-aware, so it never flags a gitignored `.env` | yes |
| `config` | Secrets in `NEXT_PUBLIC_*`, TLS verification off, production source maps, CORS `*` with credentials, insecure cookies, `Math.random` tokens, MD5/SHA1 passwords, hardcoded JWT secrets, debug flags | yes (TLS-off, public secret) |
| `authz` | API routes and server actions that hit the database with no auth check, routes that trust a client-supplied user id, `/admin` routes with no real role check | yes (writes with no auth) |
| `injection` | SQL string concatenation, `dangerouslySetInnerHTML` fed by user data, `eval`, shell commands built by interpolation, SSRF, path traversal, prototype pollution | yes (request-derived SQL/eval/exec) |
| `payments` | Stripe webhooks that never verify the signature, charge amounts taken from the client, missing idempotency keys | yes |
| `backdoor` | Obfuscated base64-eval chains, hardcoded password bypasses, auth-skip flags, `process.env` dumped to a response, calls to tunnels, paste sites and bot APIs, leftover prompt-injection text | yes (obfuscated eval, literal bypass) |
| `ai-endpoints` | LLM calls made from the browser, AI routes with no auth or no spend bound, prompts built from raw input, unsanitised LLM output rendered as HTML | warn |
| `deps` | Known CVEs for your exact lockfile versions with the upgrade that fixes them, unpinned deps, install-time scripts, lockfile drift | yes (critical CVE with a fix) |

### Live site

| Check | What it catches | Inputs | Blocks a push? |
|---|---|---|---|
| `urlprobe` | Exposed `.env`/`.git`/source maps, admin routes reachable logged out, missing security headers, no rate limiting on a real auth endpoint (with a control request so a framework's default-deny is never mistaken for one) | `KEYSNAG_SITE_URL` | partial |

### Database

| Check | What it catches | Inputs | Blocks a push? |
|---|---|---|---|
| `rls` | RLS off, `USING (true)` policies, login-only policies with no ownership check, anon grants on RLS-off tables. "RLS on, no policy" is reported as the safe locked-down default it is, not a bug | `KEYSNAG_PG_URL` (read-only role) | yes |
| `storage` | Public Supabase storage buckets, wide-open storage policies, edge functions with JWT verification off, cron routes with no shared secret | `KEYSNAG_PG_URL` plus repo | yes (public bucket with user files) |

### Accounts

| Check | What it catches | Inputs | Blocks a push? |
|---|---|---|---|
| `twoaccount` | User B reading, or no-op-writing, user A's rows through the Supabase REST API. Proves the gap the way an attacker would, without changing real data | Supabase URL, anon key, two test users' JWTs | yes |

The full threat model, the evidence behind each check, severity rules and what is planned next: [docs/THREAT-MODEL-AND-CHECKS.md](docs/THREAT-MODEL-AND-CHECKS.md).

## Why you can trust it

Most scanners get switched off within a week because they cry wolf. keysnag was built around one rule: **a check may block a push only after it has proven zero false positives on a real production codebase.** Until then it warns.

That rule was tested, not assumed. Every check was run against a real production Next.js + Supabase app with 1,400 tracked files:

- The first full run produced **144 findings**. Hand-verification showed all but 28 were false positives, each with a systematic cause: a storage-key name mistaken for a secret, a Next.js JSON-LD tag mistaken for XSS, a framework's blanket 401 mistaken for an unprotected endpoint, `m.role === 'user'` mistaken for a backdoor.
- Each cause became a fix with a regression fixture reproducing the real line. The final run is **16 findings, all genuine, zero critical**: ten real dependency advisories with their upgrade versions and six medium code advisories.
- Then three rounds of independent review by a fresh reviewer that built none of it, actively trying to silence the rules. It found and forced fixes for a CVE check that was throwing away severity data, a hook that could never wake Claude, a raw password printed into a report, and a service client being counted as an admin check.

The other trust rules, all enforced in code and tests:

- **Never prints a secret.** Every value in a finding is masked to its first and last four characters.
- **Deterministic.** Rules, catalogues and live probes. No model guessing at your code, so results are the same every run.
- **Local only.** No telemetry. Network only to the site, Supabase project and database you point it at, plus one opt-out call to OSV.dev for CVE data.
- **Exceptions must justify themselves.** You can allow a finding you have reviewed, but every allow entry must state a reason and the control that bounds abuse, or keysnag refuses to run. Allowed findings still appear, as info. See [Suppressing a finding](#suppressing-a-finding).

## Controlling what blocks

```bash
keysnag scan --fail-on critical   # default: only critical findings exit non-zero
keysnag scan --fail-on off        # never block, just report (warn mode)
keysnag scan --diff main          # scope static checks to files changed since main
keysnag scan --no-osv             # skip the one third-party call (OSV.dev CVE lookup)
keysnag install --pre-commit      # also run the secret sweep on every commit
keysnag uninstall                 # remove the hooks, restore anything they chained
```

`--diff <ref>` speeds up large repos; `secrets` always sweeps the full tree, because a secret anywhere is a secret. Install adds `keysnag.report.md` and `.json` to your `.gitignore` so the report never gets swept into a commit.

## Install in Claude Code

```bash
claude plugin marketplace add Sheldon-desouza/keysnag
claude plugin install keysnag@keysnag
```

Once installed, keysnag auto-runs on every `git commit` and `git push` you make from inside Claude Code. If it finds a blocking finding it feeds it straight back to Claude, which fixes it before continuing, so you never have to notice a failed push. It also adds an on-demand command:

```
/security-check
```

That runs the scan and walks you through fixing what it finds, one finding at a time, critical first. It pairs well with Anthropic's own `security-guidance` plugin: that one reviews the diff as Claude writes; keysnag gates what actually leaves the machine, and it also works in Cursor, Codex and CI where an editor plugin cannot.

## Install as an MCP server

keysnag runs as an MCP stdio server exposing `run_security_check` (the full report) plus one `check_<name>` tool per check, so Cursor, Claude Desktop, Codex or any MCP client can call it directly:

```json
{
  "mcpServers": {
    "keysnag": {
      "command": "npx",
      "args": ["-y", "keysnag-mcp"],
      "env": {
        "KEYSNAG_REPO_DIR": "/absolute/path/to/your/project",
        "KEYSNAG_SITE_URL": "https://your-app.vercel.app"
      }
    }
  }
}
```

## Suppressing a finding

Sometimes a finding is a real match on code that is, on inspection, acceptable: an admin tool behind its own gate, a webhook that verifies signatures a different way, a public helper with no user data. keysnag lets you record that decision instead of ignoring the finding. **Every suppression must say why it is acceptable and, separately, what stops it being abused.**

Add an `allow` array to `keysnag.config.json`, or use the helper:

```bash
keysnag allow authz.route_without_auth src/app/api/public/contact/route.ts \
  --reason "Public, unauthenticated tool by design." \
  --bound "Per-IP limit of 3 per 24h (rateLimit -> 429)."
```

- `id` is a concrete finding id (`secret.stripe_key`) or a dotted prefix (`secret.`).
- `location` is a file, a `file:line`, or a glob. A location that matches everything is only allowed with a full concrete id, never a prefix.
- `reason` and `bound` are mandatory. keysnag exits 1 before scanning, naming the entry, if either is missing.

A matched finding is never dropped: it becomes `info`, gets an `[allowed]` prefix, and carries the reason and bound in every report. It just never blocks.

## Privacy

- No telemetry, no analytics, no phone-home.
- Network access only to the site, Supabase project, or database you provide. Never to a keysnag server.
- One exception: `deps` looks up known CVEs for your exact lockfile versions via OSV.dev's public API. Opt out with `--no-osv` or `KEYSNAG_ALLOW_OSV=false`; the offline hygiene rules still run.
- Secrets are always masked in findings, reports, logs and the CLI.
- The RLS and storage audits are designed for a read-only Postgres role.

## What it does not do

- It targets Next.js + Supabase apps on Vercel today. Other stacks get a clean skip, never a false result.
- The static rules are heuristics tuned to stay quiet rather than catch everything. A rule that cannot be made low-false-positive ships as a warning, not a blocker. If a finding does not apply to your code, that belongs in the allow-list with a reason, not a bug report.
- It is automated scanning, not a substitute for a professional penetration test. keysnag will never tell you your app is unhackable. It removes the defect classes behind most real breaches of AI-built apps, and nothing more.
- The cross-account write test is a bounded no-op: it writes back the exact value already there, on at most one row, only to prove the gap exists.

## Roadmap

- **Tier 2:** AST-based analysis to replace the regex heuristics in `authz`, `injection` and `config`; secrets in git history; GitHub Actions workflow injection; Vercel and Supabase auth-config assertions (rate limits, leaked-password protection); an authenticated crawl that replays every request as the other test user.
- **Tier 3:** an optional LLM review layer at push time as a plug-in check, and continuous post-deploy monitoring.

## Contributing

Every check ships with a fixture that trips it and a real-repo run that does not. If you add a rule, add both, and run `npm test`. Bug reports for a false positive should include the line that fired; that is the most valuable issue you can file.

## Licence

MIT. Built by [Sheldon de Souza](https://github.com/Sheldon-desouza) with [Keegan de Souza](https://github.com/KeeganDesouza), a recent cybersecurity graduate who contributes to the threat model and check catalogue.

---

<sub><strong>Looking for:</strong> Claude security skill · Claude cybersecurity · Codex cybersecurity · Cursor security check · Claude Code security plugin · vibe coding security · security for AI-built apps · Lovable security scanner · Bolt security · Supabase RLS checker · Supabase security audit · Next.js security gate · pre-push security hook · git pre-push security scan · secret scanner for AI-generated code · IDOR checker · Stripe webhook verification check · OSV dependency scanner · AI founder security tool · security for non-technical founders · MCP security server. keysnag is a free, open-source pre-push security gate for apps built with AI coding agents.</sub>
