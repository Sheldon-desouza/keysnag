// INTENTIONALLY INSECURE FIXTURE — never real
"use client";

import { createClient } from "@supabase/supabase-js";

// service_role must never be reachable from a client component: it bypasses RLS entirely.
const key = process.env.SUPABASE_SERVICE_ROLE_KEY;

export function DangerousClientWidget() {
  const supabase = createClient("https://demo.supabase.co", key as string);
  return null;
}
