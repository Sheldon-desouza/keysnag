// Regression fixture: a real admin route that
// imports and calls requireAdmin() before writing. Must NOT trip any authz finding:
// requireAdmin is an auth signal (route_without_auth) and a role-check signal
// (admin_route_no_role_check).
import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
import { requireAdmin } from "@/lib/auth/require-admin";

export async function POST(request: Request) {
  await requireAdmin();
  const supabase = createClient();
  const { userId } = await request.json();
  await supabase.from("mfa_factors").delete().eq("user_id", userId);
  return NextResponse.json({ ok: true });
}
