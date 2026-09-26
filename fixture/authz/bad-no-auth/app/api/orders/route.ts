// Seeded flaw for keysnag's authz check: queries the database with no auth check
// anywhere in the file. Expected finding: authz.route_without_auth (high).
import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

export async function GET() {
  const supabase = createClient();
  const { data } = await supabase.from("orders").select("*");
  return NextResponse.json({ data });
}
