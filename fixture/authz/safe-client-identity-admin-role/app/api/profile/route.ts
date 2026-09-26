// Regression fixture (LEDGER item 13d): requireRole('admin') IS an operator gate
// (its argument matches admin/owner/operator/superuser/staff), so an operator
// acting on another user's row by an explicit id must NOT fire
// authz.client_supplied_identity.
import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
import { requireRole } from "@/lib/auth/require-role";

export async function POST(req: Request) {
  await requireRole("admin");
  const supabase = createClient();
  const body = await req.json();
  const { data } = await supabase.from("profiles").select("*").eq("user_id", body.userId);
  return NextResponse.json({ data });
}
