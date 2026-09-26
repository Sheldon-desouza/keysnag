// Seeded flaw for keysnag's authz check: writes to the database with no auth check.
// Expected finding: authz.route_without_auth (critical, because it also writes).
import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

export async function DELETE(request: Request) {
  const supabase = createClient();
  const { id } = await request.json();
  await supabase.from("reports").delete().eq("id", id);
  return NextResponse.json({ ok: true });
}
