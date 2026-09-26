// Seeded flaw: fetch() whose URL is taken directly from the request query
// string, with no restriction on the target host. Expected finding:
// injection.ssrf (critical).
import type { NextRequest } from "next/server";

export async function GET(req: NextRequest) {
  const target = req.nextUrl.searchParams.get("url") ?? "";
  const res = await fetch(target);
  return new Response(await res.text());
}
