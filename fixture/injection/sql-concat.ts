// Seeded flaw: SQL built by template-literal concatenation with a request-derived
// id, fed straight into a query call. Expected finding: injection.sql_concat (critical).
import type { NextRequest } from "next/server";

export async function GET(req: NextRequest) {
  const id = req.nextUrl.searchParams.get("id");
  const rows = await db.query(`SELECT * FROM users WHERE id = ${id}`);
  return Response.json(rows);
}

declare const db: { query: (sql: string) => Promise<unknown> };
