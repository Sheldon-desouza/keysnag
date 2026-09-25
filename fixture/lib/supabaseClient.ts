// INTENTIONALLY INSECURE FIXTURE — never real
// This client file ships to the browser bundle. A real service_role key here
// would let anyone bypass RLS entirely. vibeguard's `secrets` check must
// catch this pattern.
import { createClient } from "@supabase/supabase-js";

const SUPABASE_URL = "https://demo.supabase.co";
// Fake, real-shaped service_role JWT (header.payload.signature, all base64url).
const SUPABASE_SERVICE_ROLE_KEY =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIiwiaXNzIjoic3VwYWJhc2UiLCJyZWYiOiJkZW1vIn0.ZmFrZXNpZ25hdHVyZWZha2VzaWduYXR1cmVmYWtlc2ln";

export const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
