// Fixture: LLM route with an auth check but no spend bound (isolates
// ai.llm_route_no_spend_bound at severity high, since auth is present).
import OpenAI from "openai";
import { getServerSession } from "next-auth";

const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

export async function POST(req: Request) {
  const session = await getServerSession();
  if (!session) return new Response("unauthorized", { status: 401 });
  const reply = await client.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: "static prompt" }],
  });
  return Response.json(reply);
}
