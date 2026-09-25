# vibeguard

vibeguard runs a set of local security checks against AI-built Next.js +
Supabase apps, the kind shipped fast from a prompt with no security review.
It runs entirely in your terminal, inside Claude Code, or from any MCP
client. Nothing leaves your machine except requests to the site, database,
or Supabase project URLs you supply yourself.

## What it checks

- **Secrets in your repo and your shipped bundle.** Finds live-looking API
  keys (Stripe, OpenAI, Anthropic, Google), Supabase `service_role` JWTs, and
  other high-entropy credentials, both committed to source and served to
  every visitor in your deployed JavaScript.
- **Supabase RLS and ownership.** Connects with a read-only Postgres role and
  flags tables with Row Level Security off, policies that are wide open
  (`USING (true)`), and policies that check only "is logged in" instead of
  "does this row belong to you".
- **Exposed URLs, headers, and rate limits.** Probes your live site for
  publicly reachable `.env` files, exposed `.git` folders and source maps,
  admin routes with no auth guard, missing security headers, and an
  unthrottled login/auth endpoint.
- **Cross-account data access.** Using two of your own test logins, checks
  whether user B can read or (via a bounded, no-op write) modify user A's
  rows through the Supabase REST API, the way a real attacker would.

## Quickstart

```bash
npx vibeguard scan --repo . --url https://your-app.vercel.app
```

This runs the secrets scan and the URL probe with no setup. To unlock the
database and cross-account checks, copy `.env.example` to `.env` in the repo
you're scanning and fill in what you have:

```bash
VG_REPO_DIR=.
VG_SITE_URL=https://your-app.vercel.app
VG_SUPABASE_URL=https://xxxx.supabase.co
VG_SUPABASE_ANON_KEY=eyJ...        # public anon key
VG_PG_URL=postgres://readonly:...@db.xxxx.supabase.co:5432/postgres  # READ-ONLY role
VG_TOKEN_A=eyJ...                  # a normal signed-in user's JWT (test account A)
VG_TOKEN_B=eyJ...                  # a second user's JWT (test account B)
```

`VG_PG_URL` unlocks the RLS audit. `VG_SUPABASE_URL`, `VG_SUPABASE_ANON_KEY`,
`VG_TOKEN_A`, and `VG_TOKEN_B` together unlock the cross-account test. Any
check missing what it needs is skipped, not failed, and the report says
exactly which env var would turn it on.

## Install in Claude Code

vibeguard ships as a Claude Code plugin with a `/security-check` command
that runs the scan and walks you through fixing what it finds, one finding
at a time, critical first. Install it from this repo's `plugin/` directory
per Claude Code's plugin installation instructions, then run:

```
/security-check
```

## Install as an MCP server

vibeguard also runs as an MCP stdio server, exposing a `run_security_check`
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
    "vibeguard": {
      "command": "node",
      "args": ["/absolute/path/to/vibeguard/dist/mcp.js"],
      "env": {
        "VG_REPO_DIR": "/absolute/path/to/your/project",
        "VG_SITE_URL": "https://your-app.vercel.app"
      }
    }
  }
}
```

## Privacy

- No telemetry, no analytics, no phone-home of any kind.
- Network access only ever goes to the site, Supabase project, or Postgres
  connection string you provide, never to a vibeguard-owned server.
- Secrets are always masked in findings (first 4 + last 4 characters and a
  length), never printed in full, in reports, logs, or the CLI.
- The RLS audit is designed for a read-only Postgres role; give it write
  access and it still only reads.

## Limitations

- Targets Next.js + Supabase apps deployed on Vercel right now. Other
  stacks and hosts aren't covered.
- This is best-effort automated scanning, not a substitute for a
  professional penetration test or security audit.
- The cross-account write test is a bounded no-op: it writes back the exact
  value already there, on at most one row, only to prove the access gap
  exists, never to change real data.

## Naming

`vibeguard` is a placeholder name pending final naming. Expect the package
name to change before a stable release.
