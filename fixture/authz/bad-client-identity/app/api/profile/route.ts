// Seeded flaw for keysnag's authz check: the identity used to filter the query
// comes straight from the request instead of the verified session.
// Expected finding: authz.client_supplied_identity (high). Also trips
// authz.route_without_auth (no auth call in this file either), which is expected.
import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

export async function GET(request: Request) {
  const supabase = createClient();
  const { searchParams } = new URL(request.url);
  const userId = searchParams.get("userId");

  const { data } = await supabase
    .from("profiles")
    .select("*")
    .eq("user_id", userId);

  return NextResponse.json({ data });
}
