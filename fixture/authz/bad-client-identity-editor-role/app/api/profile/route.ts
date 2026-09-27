// Regression fixture: requireRole('editor') is not an operator
// gate (only admin/owner/operator/superuser/staff roles are). Reading userId from
// the request body and filtering a query by it MUST still fire
// authz.client_supplied_identity.
import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
import { requireRole } from "@/lib/auth/require-role";

export async function POST(req: Request) {
  await requireRole("editor");
  const supabase = createClient();
  const body = await req.json();
  const { data } = await supabase.from("profiles").select("*").eq("user_id", body.userId);
  return NextResponse.json({ data });
}
