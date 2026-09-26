// Seeded flaw: a file path built from a request-derived filename and passed to
// path.join/readFile with no normalize/startsWith/allowlist guard. Expected
// finding: injection.path_traversal (critical).
import { readFile } from "node:fs/promises";
import path from "node:path";
import type { NextRequest } from "next/server";

const UPLOADS_DIR = "/srv/uploads";

export async function GET(req: NextRequest) {
  const filename = req.nextUrl.searchParams.get("filename") ?? "";
  const filePath = path.join(UPLOADS_DIR, filename);
  const contents = await readFile(filePath);
  return new Response(contents);
}
