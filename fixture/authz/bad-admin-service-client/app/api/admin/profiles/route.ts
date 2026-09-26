// Verify-cycle-2 regression: an /api/admin route that checks only LOGIN (getUser) and
// then uses a service client. `createAdminClient()` is NOT a role check. MUST fire
// authz.admin_route_no_role_check: any logged-in user can read every profile here.
import { createAdminClient } from "@/lib/supabase/admin";
import { getUser } from "@/lib/auth";

export async function GET(req: Request) {
  const user = await getUser(req);
  if (!user) return new Response("Unauthorised", { status: 401 });
  const { data } = await createAdminClient().from("profiles").select("*");
  return Response.json({ data });
}
