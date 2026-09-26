# keysnag: threat model and check catalogue

Author role: senior application-security engineer. Audience: the keysnag build team and, later, users who want to know exactly what the gate does and does not do.

## 1. What keysnag is, in one paragraph

keysnag is a pre-production security gate for apps built with AI coding agents (Claude Code, Cursor, Lovable, Bolt, v0, Replit). It runs before code reaches main and before it reaches the live site, from a git pre-push hook, a Claude Code plugin hook, a CLI, or any MCP client. It is deterministic, offline by default, and it blocks a push only on findings that are near-certain and severe. It is not a penetration test, not an LLM guessing at your code, and not a guarantee. It removes the defect classes that account for the large majority of real breaches of AI-built apps.

## 2. Threat model: how AI-built apps actually get breached

Ordered by evidence weight (Lovable CVE-2025-48757 and the 170/1,645 exposed apps, the Tea breach, Escape.tech's scan of 1,400 apps with 2,038 criticals, Veracode's 45% OWASP-fail rate, and the recurring r/vibecoding "same 7 problems" lists).

| # | Threat class | How it shows up in AI-generated code | Consequence |
|---|---|---|---|
| T1 | Secret exposure | service_role / Stripe secret / LLM keys hardcoded, committed in .env, shipped in the JS bundle, or put in NEXT_PUBLIC_* | Full DB read/write, charges, bill blow-up |
| T2 | Broken access control | No RLS, USING(true), policies that check "logged in" but not ownership, API routes trusting a client-supplied userId, admin routes with UI-only guards, IDOR by changing an id | One user reads or edits everyone's data |
| T3 | Weak authentication | Open signup by default, no rate limit on auth, leaked-password protection off, service_role used from the client | Account takeover, credential stuffing |
| T4 | Injection | Raw SQL string concatenation, dangerouslySetInnerHTML/innerHTML with user data, eval/new Function, child_process.exec with interpolation, fetch(userUrl) SSRF, path.join with request input | RCE, XSS, data theft, internal network reach |
| T5 | Payment and webhook flaws | Stripe webhook without signature verification, price or amount taken from the client, no idempotency | Free product, forged payments |
| T6 | Data over-exposure | select=* returning PII, stack traces and DB errors sent to the client, server config serialised into the RSC payload, production source maps | PII leak, reconnaissance |
| T7 | Dependency and supply chain | Known-CVE packages pinned to training-data versions, unpinned deps, typosquats, postinstall scripts, worm-class attacks through npm | Compromise via a package you never wrote |
| T8 | Infrastructure misconfiguration | Missing security headers, CORS * with credentials, cookies without Secure/HttpOnly/SameSite, public storage buckets, edge functions without JWT verification, cron endpoints without a secret | Clickjacking, session theft, open data |
| T9 | Insecure defaults the model reaches for | TLS verification disabled, Math.random for tokens, weak hashing, debug mode on, verbose errors | Silent weakening of every other control |
| T10 | Backdoors and malicious code | Obfuscated or base64-eval blobs, hardcoded bypass conditions, hidden master passwords, unexpected outbound hosts, prompt-injection artifacts left in generated code | Persistent covert access |
| T11 | AI-feature abuse | LLM calls from the browser with a key, LLM routes with no auth or rate limit, prompts built from raw user input | Bill blow-up, prompt injection, data exfiltration through the model |
| T12 | Business-logic flaws | Anything requiring understanding of intent | Not automatable deterministically; Tier 3 |

## 3. Design principles (non-negotiable)

1. **Precision over recall for anything that blocks.** A check may block a push only after it has run on a real, non-trivial repo with zero false positives. Until then it warns. Every dogfood on a production app to date found each new check needed this tuning (secrets 597 to 0, urlprobe control-path, rls no-policy). Noisy gates get disabled; that is the single biggest product risk.
2. **Deterministic first.** Rules, ASTs, catalogs, and live probes. An LLM review layer is a Tier 3 seam, not the core, because Anthropic's security-guidance plugin already does that inside Claude Code and keysnag's edge is running anywhere, including Cursor and CI.
3. **Local and authorised only.** No telemetry. Network only to the user's own site, Supabase, and database, plus one opt-out third-party call: OSV.dev for CVE lookups (T7), because there is no offline way to know today's CVEs. `allowOsv=false` disables it.
4. **Never print a secret.** All evidence through maskSecret. Findings carry location and a fix a coding agent can apply.
5. **Severity is calibrated to blocking.** critical = near-certain exploitable exposure (secret in bundle, RLS off on user data, cross-account read proven). high = strong signal needing a human look. medium/low/info = advisory. Default gate: block on critical only.
6. **Control requests and dedup everywhere.** Any live probe compares against a control (a path that certainly does not exist). Any pattern rule dedups against a more specific rule that matched the same value.
7. **Every check ships with a fixture that trips it and a real-repo run that does not.**

## 4. Check catalogue

Status key: SHIPPED = exists and dogfooded. T1/T2/T3 = build tier. Each check: id prefix, what it detects, evidence source, severity, block-eligible.

### Tier 1: build now (deterministic, low false-positive, gate-worthy)

| Check | Detects | Source | Severity | Blocks |
|---|---|---|---|---|
| `secrets` (SHIPPED) | Service_role JWT, Stripe/OpenAI/Anthropic/Google keys, generic credentials in tracked files and the shipped bundle; git-aware; value-must-look-like-a-secret | repo + site | critical/high | yes |
| `rls` (SHIPPED) | RLS off, USING(true), login-only policies, anon grants on RLS-off tables; RLS-on-no-policy is INFO | read-only pg | critical/high/medium | yes |
| `twoaccount` (SHIPPED) | User B reads or no-op-writes user A's rows via PostgREST | supabase + 2 JWTs | critical | yes |
| `urlprobe` (SHIPPED) | .env/.git/.map exposure, admin routes logged-out, missing headers, rate limit with control path | site | critical/medium | partial |
| `authz` (NEW) | Next.js route handlers and server actions that query the DB with no auth check; routes that take `userId`/`user_id`/`owner` from body/query/params (client-trusted identity); `/admin` or `/api/admin` routes with no role check; server actions exported without auth | repo (static) | high, critical when the route also writes | warn until dogfooded, then block on critical |
| `injection` (NEW) | SQL built by string concat or template literal into `.rpc`/`sql`/`query`; `dangerouslySetInnerHTML`/`innerHTML` fed by a variable; `eval`/`new Function`; `child_process.exec`/`execSync` with interpolation; `fetch(`/`axios(` whose URL derives from request input (SSRF); `path.join`/`readFile` with request input (traversal); `JSON.parse` on request body into object spread (prototype pollution) | repo (static) | critical for eval/exec/SQL-concat with request input, high otherwise | yes for critical |
| `deps` (NEW) | Known CVEs for the exact lockfile versions via OSV.dev batch API; unpinned or `latest`; packages on a known-malicious/typosquat list; `postinstall`/`preinstall` scripts in deps; lockfile missing or stale vs package.json | repo lockfile + OSV | critical/high per CVSS, medium for hygiene | yes for critical CVE with a fix available |
| `config` (NEW) | `NEXT_PUBLIC_*` carrying a secret-shaped value; service_role referenced in client-reachable code; `NODE_TLS_REJECT_UNAUTHORIZED=0` or `rejectUnauthorized:false`; `productionBrowserSourceMaps:true`; CORS `*` with credentials; `Set-Cookie` without Secure/HttpOnly/SameSite; debug/verbose error flags; Math.random used for tokens/ids; md5/sha1 for passwords; hardcoded JWT secret | repo (static) | critical for TLS-off and public-secret, high otherwise | yes for critical |
| `payments` (NEW) | Stripe webhook route without `constructEvent`/signature check; price/amount/currency read from request body into a charge or checkout session; missing idempotency key on charge creation | repo (static) | critical for unverified webhook and client-priced charge | yes |
| `storage` (NEW) | Supabase storage buckets that are public or have permissive policies; edge functions deployed with JWT verification off; cron/internal routes with no shared-secret check | read-only pg + repo | high/critical | yes for public bucket with user files |
| `backdoor` (NEW) | Obfuscated code (long base64 passed to eval/Function/atob chains), hardcoded bypass conditionals (`if (password === "...")`, `=== "admin"` literal checks), hidden auth-skip flags, unexpected outbound hosts in server code, `process.env` dumped to a response, prompt-injection artifacts ("ignore previous instructions") inside generated code | repo (static) | critical for eval-obfuscation and literal bypass, high otherwise | yes for critical |
| `ai-endpoints` (NEW) | LLM SDK calls from client components; API routes that call an LLM with no auth or rate limit; prompts built directly from raw user input with no delimiter/guard | repo (static) | high | warn |

### Tier 2: next (higher precision or more inputs)

- AST-based analysis (ts-morph) to replace regex in `authz`, `injection`, `config` once Tier 1 proves the rules.
- Secrets in git history (`git log -p` sweep), not just the working tree.
- CI/CD: GitHub Actions workflow injection (`${{ github.event.* }}` in run:), secrets echoed, `pull_request_target` misuse.
- Vercel: env vars exposed to the client, unprotected preview deployments, cron routes without CRON_SECRET.
- Supabase auth config assertion via the Management API: rate limits, leaked-password protection, email confirmation, MFA availability. This is where the real "is login rate limited" signal lives for Supabase apps.
- Authenticated DAST crawl with the two test users: replay every discovered request as the other user (generalises `twoaccount` beyond PostgREST).
- SBOM export and licence check.

### Tier 3: seams, not core

- Optional LLM diff review at push time for business-logic and authz reasoning, behind an explicit opt-in and API key. Designed as a `Check` that consumes the diff, so it plugs into the same runner and report.
- Continuous post-deploy monitoring (the paid product from the market assessment): log-based attack detection, RLS drift, bundle secret drift, bill-spike alerts.

## 5. Gate behaviour

- `keysnag scan --fail-on critical` (default in hooks). Exit 0 = pass, exit 2 = block, with a one-line reason and the report path. `--fail-on off` = warn only.
- `keysnag install` writes `.git/hooks/pre-push` (idempotent, preserves an existing hook by chaining) that runs the full secret sweep plus every repo-static check on the tracked tree. Live checks (rls, twoaccount, urlprobe, storage) run in the hook only if their inputs are present in .env, never blocking on network failure.
- `keysnag install --pre-commit` also adds a lighter pre-commit that runs `secrets` on staged files only.
- Claude Code plugin hook: PostToolUse on `git commit` and `git push` runs the same scan and feeds blocking findings back to Claude with an asyncRewake, mirroring security-guidance's mechanism, so Claude fixes them before the push proceeds.
- `--diff <ref>` scopes repo-static checks to files changed since `<ref>` for speed on very large repos; `secrets` still sweeps the full tree because a secret anywhere is a secret.

## 6. What keysnag will say about itself (copy guardrails)

- Tagline: **Cybersecurity for AI founders and vibe coders.** Sub: the pre-push security gate for apps built with Claude Code, Cursor, Lovable and Bolt.
- Never: "unhackable", "guaranteed", "certified", "badge". The community mocks these and they create liability.
- Always: "catches the defect classes that actually breach AI-built apps", "not a substitute for a professional penetration test", "runs locally, nothing leaves your machine (except an optional CVE lookup to OSV.dev)".

## 7. Acceptance for any new check

1. Fixture file(s) under `fixture/` that trip it, with the expected finding ids listed in `fixture/README.md`.
2. A run on the real a production app repo with every finding hand-verified: zero false positives before the check may block; otherwise it ships as warn.
3. Evidence masked, location precise (file:line), fix phrased for a coding agent.
4. Unit test for the rule logic and a test that it skips cleanly with missing inputs.
5. Listed in the README "what it checks" table with its Tier and block status.
