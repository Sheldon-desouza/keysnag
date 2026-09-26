// INTENTIONALLY INSECURE FIXTURE — never real
import { NextResponse } from "next/server";

export async function GET() {
  const res = NextResponse.json({ ok: true });
  // Allowing any origin while also allowing credentials lets any site read
  // authenticated responses on a signed-in user's behalf.
  res.headers.set("Access-Control-Allow-Origin", "*");
  res.headers.set("Access-Control-Allow-Credentials", "true");
  return res;
}
