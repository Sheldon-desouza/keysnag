// Seeded flaw: dangerouslySetInnerHTML fed by a request-derived comment body (read
// straight from the incoming request, then rendered without sanitisation).
// Expected finding: injection.dangerous_html (high, request-derived).
import type { NextRequest } from "next/server";

export async function CommentBlock({ req }: { req: NextRequest }) {
  const body = await req.json();
  const html = body.comment;
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
