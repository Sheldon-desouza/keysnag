# keysnag

**Cybersecurity for AI founders and vibe coders.**
The pre-push security gate for apps built with Claude Code, Cursor, Lovable and Bolt.

keysnag is a deterministic, offline-by-default security gate. It runs from a
git pre-push hook, a Claude Code plugin hook, the CLI, or any MCP client, and
it blocks a push only on findings that are near-certain and severe. It is not
a penetration test, not an LLM guessing at your code, and not a guarantee. It
catches the defect classes that actually breach AI-built apps, it is not a
substitute for a professional penetration test, and it runs locally, nothing
leaves your machine (except an optional CVE lookup to OSV.dev).

## What it checks

12 checks, grouped by what they need to run. Every check is skipped, never
failed, if its inputs are missing, and the report says exactly which env var
would turn it on. "Blocks a push?" reflects the default gate (`--fail-on
critical`): only findings at critical severity stop a push; everything else
is reported and left for you to triage.

### Repo / static (no inputs beyond the code itself)

| Check | What it catches | Inputs needed | Blocks a push? |
|---|---|---|---|
| `secrets` | API keys, service_role JWTs, and other credentials hardcoded or committed where they'll reach a client bundle | none (repo) | yes |
| `config` | Public env secrets, TLS verification off, prod source maps, CORS `*` with credentials, insecure cookies, weak randomness/hashing, hardcoded JWT secrets, debug flags left on | none | yes (TLS-off and public-secret) |
| `authz` | API routes and server actions that touch the database with no auth check, routes that trust a client-supplied user id, `/admin` routes with no role check | none | yes (writes with no auth) |
| `injection` | SQL string concatenation, `dangerouslySetInnerHTML`/`innerHTML`, `eval`/`new Function`, shell commands built by interpolation, SSRF, path traversal, prototype pollution | none | yes (request-derived SQL/eval/exec) |
| `payments` | Stripe webhooks that never verify the signature, charge amounts taken from the client, missing idempotency keys | none | yes |
| `backdoor` | Obfuscated base64-eval chains, hardcoded password/role bypasses, auth-skip flags, `process.env` dumped to a response, calls to unexpected outbound hosts, leftover prompt-injection text | none | yes (obfuscated eval, literal bypass) |
| `ai-endpoints` | LLM calls made straight from the browser, AI routes with no auth or no spend bound, prompts built from raw request input, unsanitised LLM output rendered as HTML | none | warn (not yet gate-eligible) |
| `deps` | Known CVEs in your exact lockfile versions, unpinned/`latest` deps, install-time lifecycle scripts, lockfile drift | lockfile (`package-lock.json`/`pnpm-lock.yaml`/`yarn.lock`) | yes (critical CVE with a fix available) |

### Live site

| Check | What it catches | Inputs needed | Blocks a push? |
|---|---|---|---|
| `urlprobe` | Exposed `.env`/`.git`/source maps, admin routes reachable while logged out, missing security headers, no rate limiting on auth | `KEYSNAG_SITE_URL` | partial |

### Database

| Check | What it catches | Inputs needed | Blocks a push? |
|---|---|---|---|
| `rls` | Row Level Security off, `USING (true)` policies, login-only policies with no ownership check, anon grants on RLS-off tables | `KEYSNAG_PG_URL` (read-only role) | yes |
| `storage` | Public Supabase storage buckets, wide-open storage policies, edge functions with JWT verification off, cron/internal routes with no shared secret | `KEYSNAG_PG_URL` for buckets/policies; repo-static for edge functions and cron routes | yes (public bucket with user files) |

### Accounts

| Check | What it catches | Inputs needed | Blocks a push? |
|---|---|---|---|
| `twoaccount` | User B reading or no-op-writing user A's rows through the Supabase REST API, proving an access gap the way a real attacker would | `KEYSNAG_SUPABASE_URL`, `KEYSNAG_SUPABASE_ANON_KEY`, `KEYSNAG_TOKEN_A`, `KEYSNAG_TOKEN_B` | yes |

See [docs/THREAT-MODEL-AND-CHECKS.md](docs/THREAT-MODEL-AND-CHECKS.md) for the
full threat model, the evidence behind each check, and what's planned next.

## Quickstart

```bash
npx keysnag scan
```

Runs the secrets scan and every repo-static check with no setup. Point it at
a live site or database to unlock more:

```bash
npx keysnag scan --repo . --url https://your-app.vercel.app
```

Copy `.env.example` to `.env` in the repo you're scanning and fill in what
you have to unlock `rls`, `twoaccount`, and the `storage` bucket/policy audit:

```bash
KEYSNAG_REPO_DIR=.
KEYSNAG_SITE_URL=https://your-app.vercel.app
KEYSNAG_SUPABASE_URL=https://xxxx.supabase.co
KEYSNAG_SUPABASE_ANON_KEY=eyJ...        # public anon key
KEYSNAG_PG_URL=postgres://readonly:...@db.xxxx.supabase.co:5432/postgres  # READ-ONLY role
KEYSNAG_TOKEN_A=eyJ...                  # a normal signed-in user's JWT (test account A)
KEYSNAG_TOKEN_B=eyJ...                  # a second user's JWT (test account B)
```

### Installing the gate

```bash
keysnag install
```

Writes a real `.git/hooks/pre-push` that runs the full secret sweep plus
every repo-static check on the tracked tree (it works the same whether you
push from Cursor, VS Code's terminal, a bare terminal, or CI, because it's a
plain git hook, not an editor extension). Live checks (`rls`, `twoaccount`,
`urlprobe`, `storage`) only run in the hook if their `.env` inputs are
present, and never block on a network failure. If a hook is already
installed, keysnag chains it rather than overwriting it.

```bash
keysnag install --pre-commit
```

Also installs a lighter pre-commit hook that runs `secrets` on staged files
only, so a leaked key never even makes it into a commit.

```bash
keysnag uninstall
```

Removes keysnag's hooks and restores anything they were chained in front of.

### Controlling what blocks

```bash
keysnag scan --fail-on critical   # default: only critical findings exit non-zero
keysnag scan --fail-on off        # never block, just report (warn mode)
keysnag scan --diff main          # scope repo-static checks to files changed since `main`
keysnag scan --no-osv             # skip the one third-party call (OSV.dev CVE lookup)
```

`--diff <ref>` speeds up large repos by scoping repo-static checks to files
changed since `<ref>`; `secrets` always sweeps the full tree, because a
secret anywhere is a secret.

Suppressing a finding you've reviewed and accepted is covered in
[Suppressing a finding](#suppressing-a-finding) below.

## Install in Claude Code

keysnag ships as a Claude Code plugin. Install it from this repo's `plugin/`
directory per Claude Code's plugin installation instructions. Once
installed, it auto-runs on every `git commit` and `git push` you make from
inside Claude Code: a `PostToolUse` hook re-runs the scan and, if it finds a
blocking (critical) finding, feeds it straight back to Claude so Claude fixes
it before continuing, instead of you having to notice a failed push. It also
adds a `/security-check` command that runs the scan on demand and walks you
through fixing what it finds, one finding at a time, critical first:

```
/security-check
```

## Install as an MCP server

keysnag also runs as an MCP stdio server, exposing a `run_security_check`
tool (the full report) plus one `check_<name>` tool per check, for any MCP
client to call directly:

```bash
npm run mcp
# or, once built:
node dist/mcp.js
```

Sample MCP client config (Cursor, Claude Desktop, or any client that reads
this shape):

```json
{
  "mcpServers": {
    "keysnag": {
      "command": "node",
      "args": ["/absolute/path/to/keysnag/dist/mcp.js"],
      "env": {
        "KEYSNAG_REPO_DIR": "/absolute/path/to/your/project",
        "KEYSNAG_SITE_URL": "https://your-app.vercel.app"
      }
    }
  }
}
```

## Suppressing a finding

Sometimes a finding is a real match on a route that is, on inspection, genuinely
acceptable, an admin tool behind its own gate, a webhook that verifies signatures a
different way, a cheap helper with no user data. keysnag lets you record that
decision instead of just ignoring the finding, the same discipline a production app's own
`an exceptions-baseline script` enforces for exceptions: **every suppression
must say why it's acceptable and, separately, what stops it being abused.**

Add an `allow` array to `keysnag.config.json`:

```json
{
  "allow": [
    {
      "id": "authz.route_without_auth",
      "location": "src/app/api/public/contact/route.ts",
      "reason": "Public, unauthenticated tool by design.",
      "bound": "Per-IP limit of 3 per 24h (rateLimit -> 429)."
    }
  ]
}
```

- `id` matches a finding if it equals the finding's id, or is a prefix of it
  (e.g. `"secret."` matches `secret.stripe_key`).
- `location` matches the finding's `location` exactly, matches just the file part
  before the `:line`, or is a glob (`*` and `**` are supported, no extra
  dependency).
- Both `reason` and `bound` are **mandatory and must be non-empty**. `reason` is
  why this is acceptable; `bound` is the actual compensating control, a rate
  limit, a quota, a plan gate, an auth check, or an explicit "no user data".
  keysnag refuses to run at all, exiting 1 with the offending entries named,
  if any allow entry is missing either. An exception with no stated bound is
  not an exception, it's a hole with no story attached.

A matched finding is never dropped. It is downgraded to `info` severity, its
title is prefixed `[allowed] `, and its detail gets the reason and bound
appended, so it still shows up in every report, it just never blocks a push.

Use the CLI helper instead of hand-editing the file:

```bash
keysnag allow authz.route_without_auth src/app/api/public/contact/route.ts \
  --reason "Public, unauthenticated tool by design." \
  --bound "Per-IP limit of 3 per 24h (rateLimit -> 429)."
```

It creates `keysnag.config.json` if it doesn't exist, appends to any existing
`allow` array, and refuses (no write) if `--reason` or `--bound` is empty.

## Privacy

- No telemetry, no analytics, no phone-home of any kind.
- Network access only ever goes to the site, Supabase project, or Postgres
  connection string you provide yourself, never to a keysnag-owned server.
- The one exception: `deps` looks up known CVEs for your exact lockfile
  versions via OSV.dev's public batch API. Opt out with `--no-osv` or
  `KEYSNAG_ALLOW_OSV=false`; the check still runs its offline hygiene rules
  (unpinned deps, install scripts, lockfile drift) and reports one `info`
  finding noting the CVE lookup was skipped.
- Secrets are always masked in findings (first 4 + last 4 characters and a
  length), never printed in full, in reports, logs, or the CLI.
- The RLS and storage audits are designed for a read-only Postgres role;
  give one write access and it still only reads.

## Limitations

- Targets Next.js + Supabase apps deployed on Vercel right now. Other
  stacks and hosts get a clean skip, not a false result.
- The static rules (`authz`, `injection`, `config`, `payments`, `backdoor`,
  `ai-endpoints`) are heuristics, tuned to stay quiet rather than to catch
  everything: a rule that can't be made low-false-positive ships as a
  warning, never a blocker, until it's been run against a real repo with
  zero false positives. If a finding doesn't apply to your code, that goes
  in the [allow-list](#suppressing-a-finding) with a reason and a bound, not
  a bug report.
- This is best-effort automated scanning, not a substitute for a
  professional penetration test or security audit. keysnag will never claim
  your app is "unhackable", "guaranteed", or "certified"; it removes the
  defect classes that account for most real breaches of AI-built apps, and
  nothing more.
- The cross-account write test is a bounded no-op: it writes back the exact
  value already there, on at most one row, only to prove the access gap
  exists, never to change real data.

Full threat model and check-by-check rationale:
[docs/THREAT-MODEL-AND-CHECKS.md](docs/THREAT-MODEL-AND-CHECKS.md).

## Naming

name to change before a stable release.
