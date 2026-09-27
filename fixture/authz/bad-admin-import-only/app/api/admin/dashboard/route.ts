// Regression fixture: the only mention of "admin" anywhere in
// this file is the import path (@/lib/admin-utils) and the route path itself.
// There is no actual role/admin check call. MUST STILL fire
// authz.admin_route_no_role_check, and the location must be the line of the
// exported GET handler, not always :1.
import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
import { formatDashboard } from "@/lib/admin-utils";

export async function GET() {
  const supabase = createClient();
  const { data } = await supabase.from("dashboard_stats").select("*");
  return NextResponse.json(formatDashboard(data));
}
