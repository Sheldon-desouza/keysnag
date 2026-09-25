// INTENTIONALLY INSECURE FIXTURE — never real
// Admin API route with no auth check: returns sensitive data to anyone.
// keysnag's `urlprobe` check must catch this route being reachable while
// logged out.
import { NextResponse } from "next/server";
import { supabase } from "../../../lib/supabaseClient";

export async function GET() {
  // No session check, no role check — served with the service_role client.
  const { data } = await supabase.from("profiles").select("*");
  return NextResponse.json({ users: data ?? [] });
}
