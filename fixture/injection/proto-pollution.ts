// Seeded flaw: a parsed request body is spread/Object.assign'd into a config
// object with no __proto__ guard. Expected finding: injection.proto_pollution
// (medium).
export async function POST(request: Request) {
  const rawBody = await request.text();
  const config: Record<string, unknown> = {};
  const merged = Object.assign(config, JSON.parse(rawBody));
  return Response.json(merged);
}
