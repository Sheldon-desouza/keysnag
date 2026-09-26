// Operator route: an admin repairs another user's row by explicit id. This is the
// legitimate use of a client-supplied identity because requireAdmin removes the
// ordinary-user caller the IDOR rule targets. MUST NOT trip authz.client_supplied_identity.
import { requireAdmin } from "@/lib/admin";
import { supabase } from "@/lib/supabase";

export async function POST(req: Request) {
  await requireAdmin(req);
  const body = await req.json();
  const { data } = await supabase.from("subscriptions").select("*").eq("user_id", body.userId);
  return Response.json({ data });
}
