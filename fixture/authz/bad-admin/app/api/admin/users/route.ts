// Seeded flaw for keysnag's authz check: a privileged-looking path with no
// permission gate of any kind in the handler body.
// Expected finding: authz.admin_route_no_role_check (high). Also trips
// authz.route_without_auth (no auth call in this file either), which is expected.
import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

export async function GET() {
  const supabase = createClient();
  const { data } = await supabase.from("users").select("*");
  return NextResponse.json({ data });
}
