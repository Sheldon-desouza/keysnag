// Regression fixture (LEDGER item 11, authz.ts bullet I): an auth-flow route,
// public by design and rate-limited elsewhere, using a service client with no
// session check. /api/auth/ is skipped entirely, so this must trip no finding.
import { NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase/service";

export async function GET(request: Request) {
  const supabase = createServiceClient();
  const { searchParams } = new URL(request.url);
  const email = searchParams.get("email");
  const { data } = await supabase.from("auth_confirmations").select("confirmed").eq("email", email).single();
  return NextResponse.json({ confirmed: Boolean(data?.confirmed) });
}
