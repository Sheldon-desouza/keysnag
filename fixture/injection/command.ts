// Seeded flaw: a shell command built by interpolating a request-derived filename
// into execSync. Expected finding: injection.command (critical).
import { execSync } from "node:child_process";
import type { NextRequest } from "next/server";

export async function GET(req: NextRequest) {
  const filename = req.nextUrl.searchParams.get("filename");
  const output = execSync(`cat /var/data/${filename}`);
  return new Response(output);
}
