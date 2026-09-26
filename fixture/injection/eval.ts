// Seeded flaw: eval() run directly on request-derived input. Expected finding:
// injection.eval (critical).
import type { NextRequest } from "next/server";

export async function POST(req: NextRequest) {
  const body = await req.json();
  const result = eval(body.expression);
  return Response.json({ result });
}
