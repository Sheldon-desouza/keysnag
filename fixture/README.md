# vibeguard fixture — deliberately insecure demo

**This project is intentionally broken. It exists only so vibeguard's own
tests can prove every check fires. It must never be deployed, never given
real credentials, and never used as a starting point for a real app.**

Every secret in this folder is fake and real-shaped (correct format, no live
value). Every schema flaw and every route is a known, seeded vulnerability.

## Seeded flaw -> expected vibeguard check

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

## Do not

- Do not deploy this to Vercel or anywhere else.
- Do not replace any fake key with a real one, even temporarily.
- Do not run `supabase db push` with this migration against a real project.
