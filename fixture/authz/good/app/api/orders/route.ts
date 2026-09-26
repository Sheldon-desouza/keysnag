// The correctly-guarded counterpart: verifies the session before any data access
// and derives the identity used in the query filter from that session, never
// from the request. Must NOT trip any authz finding.
import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

export async function GET() {
  const supabase = createClient();
  const {
    data: { user },
    error,
  } = await supabase.auth.getUser();

  if (error || !user) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }

  const { data, error: queryError } = await supabase
    .from("orders")
    .select("*")
    .eq("user_id", user.id);

  if (queryError) {
    return NextResponse.json({ error: "failed" }, { status: 500 });
  }

  return NextResponse.json({ data });
}
