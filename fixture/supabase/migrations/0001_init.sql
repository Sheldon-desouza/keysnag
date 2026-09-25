-- INTENTIONALLY INSECURE FIXTURE — never real
-- Documents the intended-broken schema for keysnag's `rls` check to parse.
-- This SQL is never run against a live database as part of the fixture.

create table profiles (
  id uuid primary key references auth.users(id),
  email text,
  full_name text
);
-- RLS DISABLED: any authenticated (or anon, via PostgREST) request can read
-- every user's profile.

create table user_roles (
  user_id uuid primary key references auth.users(id),
  role text not null default 'user'
);
-- RLS DISABLED: anyone can read/write role assignments, including their own
-- privilege escalation to 'admin'.

create table subscriptions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id),
  plan text,
  status text
);
alter table subscriptions enable row level security;
-- Policy enabled but effectively open: USING (true) applies to every row,
-- so any signed-in user can read every other user's subscription.
create policy "subscriptions_open" on subscriptions
  for select
  using (true);

create table orders (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id),
  total_cents integer,
  status text
);
alter table orders enable row level security;
-- Policy checks the caller is signed in but never checks ownership, so any
-- authenticated user can read any other user's orders (see the IDOR route).
create policy "orders_authenticated_no_ownership" on orders
  for select
  using (auth.role() = 'authenticated');

-- Anonymous (unauthenticated) role can select orders directly via PostgREST,
-- bypassing the need to even be signed in.
grant select on orders to anon;
