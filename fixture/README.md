# keysnag fixture — deliberately insecure demo

**This project is intentionally broken. It exists only so keysnag's own
tests can prove every check fires. It must never be deployed, never given
real credentials, and never used as a starting point for a real app.**

Every secret in this folder is fake and real-shaped (correct format, no live
value). Every schema flaw and every route is a known, seeded vulnerability.

## Seeded flaw -> expected keysnag check

| Flaw | Where | Expected check |
|---|---|---|
| Service_role JWT hardcoded in a client file | `fixture/lib/supabaseClient.ts` | `secrets` |
| Stripe `sk_live_` key hardcoded in a client component | `fixture/app/page.tsx` | `secrets` |
| OpenAI `sk-` key hardcoded in a client component | `fixture/app/page.tsx` | `secrets` |
| Service_role key committed in `.env.local` | `fixture/.env.local` | `secrets` |
| `profiles`, `user_roles` tables with RLS disabled | `fixture/supabase/migrations/0001_init.sql` | `rls` |
| `subscriptions` policy `USING (true)` (open to any signed-in user) | `fixture/supabase/migrations/0001_init.sql` | `rls` |
| `orders` policy checks `auth.role() = 'authenticated'` only, no ownership | `fixture/supabase/migrations/0001_init.sql` | `rls` |
| `GRANT SELECT ON orders TO anon` | `fixture/supabase/migrations/0001_init.sql` | `rls` |
| Admin page with no auth guard | `fixture/app/admin/page.tsx` | `urlprobe` |
| Admin API route with no auth check | `fixture/app/api/admin/route.ts` | `urlprobe` |
| Order lookup by id with no ownership check (IDOR) | `fixture/app/api/orders/[id]/route.ts` | `twoaccount` |

### authz

| Flaw | Where | Expected id | Severity |
|---|---|---|---|
| Route queries the DB with no auth call in the file | `fixture/authz/bad-no-auth/app/api/orders/route.ts` | `authz.route_without_auth` | high |
| Route writes to the DB with no auth call | `fixture/authz/bad-write-no-auth/app/api/reports/route.ts` | `authz.route_without_auth` | critical |
| Query filtered by a client-supplied `userId` instead of the session | `fixture/authz/bad-client-identity/app/api/profile/route.ts` | `authz.client_supplied_identity` | high |
| `/admin` route with no role/admin check | `fixture/authz/bad-admin/app/api/admin/users/route.ts` | `authz.admin_route_no_role_check` | high |
| Correctly-guarded counterpart (must stay clean) | `fixture/authz/good/app/api/orders/route.ts` | none | - |

### injection

| Flaw | Where | Expected id | Severity |
|---|---|---|---|
| SQL built by template-literal concat with a request-derived id | `fixture/injection/sql-concat.ts` | `injection.sql_concat` | critical |
| `dangerouslySetInnerHTML` fed by a non-literal variable | `fixture/injection/dangerous-html.tsx` | `injection.dangerous_html` | high |
| `eval()` run on request-derived input | `fixture/injection/eval.ts` | `injection.eval` | critical |
| Shell command built by interpolating a request-derived filename into `execSync` | `fixture/injection/command.ts` | `injection.command` | critical |
| `fetch()` whose URL comes straight from the request query string (SSRF) | `fixture/injection/ssrf.ts` | `injection.ssrf` | critical |
| File path built from a request-derived filename with no guard | `fixture/injection/path-traversal.ts` | `injection.path_traversal` | critical |
| Parsed request body spread/`Object.assign`'d into a config object with no `__proto__` guard | `fixture/injection/proto-pollution.ts` | `injection.proto_pollution` | medium |
| Safe counterpart (must stay clean) | `fixture/injection/safe.ts` | none | - |

### deps

| Flaw | Where | Expected id | Severity |
|---|---|---|---|
| Dependency pinned to a known-vulnerable version (unit-tested with an injected fake OSV response; a live OSV.dev lookup runs when network is allowed) | `fixture/deps/package.json` + `fixture/deps/package-lock.json` | `deps.known_cve` | critical/high/medium per CVSS |
| Dependency declared as `"latest"`/`"*"` or with no lockfile | `fixture/deps/package.json` | `deps.unpinned` | medium |
| Dependency with a `preinstall`/`postinstall` lifecycle script | `fixture/deps/package.json` (with `node_modules` present) | `deps.install_script` | medium |
| `package.json` dependency missing from the lockfile | `fixture/deps/package.json` vs `fixture/deps/package-lock.json` | `deps.lockfile_stale` | low |
| OSV.dev unreachable (offline / `--no-osv`) | any run with `allowOsv: false` | `deps.osv_unavailable` | info |

### config

| Flaw | Where | Expected id | Severity |
|---|---|---|---|
| `NEXT_PUBLIC_` variable carrying a secret-shaped value | `fixture/config/public-env-secret.env` | `config.public_env_secret` | critical (high if name-only signal) |
| `service_role` referenced in a `"use client"` file | `fixture/config/service-role-in-client.tsx` | `config.service_role_in_client` | high |
| TLS certificate verification disabled | `fixture/config/tls-verification-off.ts` | `config.tls_verification_off` | critical |
| `productionBrowserSourceMaps: true` | `fixture/config/source-maps-prod.next.config.js` | `config.source_maps_prod` | high |
| CORS `*` together with credentials | `fixture/config/cors-wildcard-credentials.ts` | `config.cors_wildcard_credentials` | high |
| Cookie set without `httpOnly`/`secure`/`sameSite` | `fixture/config/insecure-cookie.ts` | `config.insecure_cookie` | high |
| `Math.random()` used to build a token/id | `fixture/config/weak-random-token.ts` | `config.weak_random_token` | high |
| MD5/SHA1 used to hash a password | `fixture/config/weak-hash-password.ts` | `config.weak_hash_password` | high |
| `jwt.sign`/`verify` called with a hardcoded secret literal | `fixture/config/hardcoded-jwt-secret.ts` | `config.hardcoded_jwt_secret` | high |
| Debug mode left on in production config | `fixture/config/.env.production` | `config.debug_on` | medium |
| Anon key in a `NEXT_PUBLIC_` var (must stay clean) | `fixture/config/safe-anon-key.env` | none | - |
| Safe counterpart (must stay clean) | `fixture/config/safe.ts` | none | - |

### payments

| Flaw | Where | Expected id | Severity |
|---|---|---|---|
| Stripe webhook route that never verifies the signature | `fixture/payments/webhook-unverified.ts` | `payments.webhook_unverified` | critical |
| Charge/session amount taken from the request body | `fixture/payments/client-priced-charge.ts` | `payments.client_priced_charge` | critical |
| `charges`/`paymentIntents.create` with no idempotency key | `fixture/payments/no-idempotency.ts` | `payments.no_idempotency` | low |
| Safe counterpart (must stay clean) | `fixture/payments/safe.ts` | none | - |

### storage

| Flaw | Where | Expected id | Severity |
|---|---|---|---|
| Storage bucket with `public = true` (needs a live `pgUrl`; no offline fixture, requires a real Supabase project) | n/a | `storage.public_bucket` | high (critical if the name suggests user uploads) |
| Storage object policy `USING (true)` (needs a live `pgUrl`; no offline fixture) | n/a | `storage.policy_wide_open` | high |
| Edge function deployed with `verify_jwt = false` | `fixture/storage/supabase/config.toml` | `storage.edge_fn_no_jwt` | high |
| Cron/internal route with no shared-secret check | `fixture/storage/app/api/cron/sync/route.ts` | `storage.cron_no_secret` | high |
| Cron route that does check a shared secret (must stay clean) | `fixture/storage/app/api/cron/safe/route.ts` | none | - |
| pg connection unreachable | any run with a bad `pgUrl` | `storage.connect_failed` | info |

### backdoor

| Flaw | Where | Expected id | Severity |
|---|---|---|---|
| Obfuscated base64-eval chain | `fixture/backdoor/obfuscated_eval.ts` | `backdoor.obfuscated_eval` | critical |
| Hardcoded credential literal bypass (password/passwd/pin/secret/masterKey/apiKey) | `fixture/backdoor/literal_bypass.ts` | `backdoor.literal_bypass` | critical |
| Auth-skip flag short-circuits an auth check | `fixture/backdoor/auth_skip_flag.ts` | `backdoor.auth_skip_flag` | high |
| `process.env` serialised/sent into a response or log | `fixture/backdoor/env_dump.ts` | `backdoor.env_dump` | high |
| Outbound call to an exfil/tunnel host (raw IP, ngrok, telegram bot, etc.) | `fixture/backdoor/suspicious_outbound.ts` | `backdoor.suspicious_outbound` | high |
| Prompt-injection attack phrase inside a string literal | `fixture/backdoor/prompt_injection_artifact.ts` | `backdoor.prompt_injection_artifact` | low |
| Safe counterpart (must stay clean) | `fixture/backdoor/safe.ts` | none | - |
| Safe: role-literal discriminated-union checks (`m.role === 'user'`, `c.role === 'performance'`) | `fixture/backdoor/safe-role-literal.ts` | none | - |
| Safe: legitimate provider integrations (fal.run, perplexity, amazon) | `fixture/backdoor/safe-outbound.ts` | none | - |
| Safe: comment/docstring mentioning "system prompt" with no attack phrase | `fixture/backdoor/safe-prompt-comment.ts` | none | - |
| Safe: local env merge, never serialised/sent | `fixture/backdoor/safe-env-merge.ts` | none | - |
| Safe: single named `process.env.KEY` property read, not the whole object | `fixture/backdoor/safe-env-property.ts` | none | - |

### ai-endpoints

| Flaw | Where | Expected id | Severity |
|---|---|---|---|
| LLM SDK called directly from a `"use client"` component | `fixture/ai/components/ChatWidget.tsx` | `ai.llm_call_in_client` | critical |
| LLM route with no auth check | `fixture/ai/app/api/chat/route.ts` | `ai.llm_route_no_auth` | high |
| LLM route with auth but no spend bound (rate limit) | `fixture/ai/app/api/chat-nospendbound/route.ts` | `ai.llm_route_no_spend_bound` | high (critical when also unauthenticated) |
| Prompt built directly from raw request input | `fixture/ai/app/api/chat-rawprompt/route.ts` | `ai.raw_user_prompt` | low |
| LLM output rendered as HTML with no sanitiser | `fixture/ai/components/UnsafeAnswer.tsx` | `ai.unsafe_output_render` | high |
| Clean LLM route: auth + rate limit + guarded prompt (must stay clean) | `fixture/ai/app/api/chat-safe/route.ts` | none | - |
| Sanitised LLM output render (must stay clean) | `fixture/ai/components/SafeAnswer.tsx` | none | - |

## Do not

- Do not deploy this to Vercel or anywhere else.
- Do not replace any fake key with a real one, even temporarily.
- Do not run `supabase db push` with this migration against a real project.
