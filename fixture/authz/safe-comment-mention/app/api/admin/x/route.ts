// Regression fixture: the ONLY
// mention of "admin"/"role" anywhere in this file is inside a comment, and there
// is no real role check. This MUST still fire authz.admin_route_no_role_check,
// proving comments are stripped before the role-check regex runs.
// TODO: add an admin/role check here before this ships.
import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

export async function GET() {
  const supabase = createClient();
  const { data } = await supabase.from("settings").select("*");
  return NextResponse.json({ data });
}
