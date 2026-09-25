// INTENTIONALLY INSECURE FIXTURE — never real
// IDOR: returns any order by id with no check that the caller owns it.
// vibeguard's `twoaccount` check must catch account B reading account A's
// order by guessing/incrementing the id.
import { NextResponse } from "next/server";
import { supabase } from "../../../../lib/supabaseClient";

export async function GET(
  _req: Request,
  { params }: { params: { id: string } }
) {
  // No auth.uid() === orders.user_id check — any signed-in user, or the
  // anon role (see 0001_init.sql grant), can fetch any order by id.
  const { data } = await supabase
    .from("orders")
    .select("*")
    .eq("id", params.id)
    .single();
  return NextResponse.json({ order: data ?? null });
}
