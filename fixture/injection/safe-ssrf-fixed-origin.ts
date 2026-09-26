// Safe: a server route exchanging an auth code with a fixed, hardcoded external
// origin. The request-derived value (the auth code) is only in the request body,
// never in the URL, so the host is not attacker-controlled. Must not fire
// injection.ssrf.
import type { NextRequest } from "next/server";

export async function POST(req: NextRequest) {
  const { code } = await req.json();
  const res = await fetch(`https://api.amazon.com/auth/o2/token`, {
    method: "POST",
    body: JSON.stringify({ code }),
  });
  return Response.json(await res.json());
}
