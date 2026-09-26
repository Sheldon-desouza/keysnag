// Fixture: LLM route with no auth check (rate limiting present so this file
// isolates ai.llm_route_no_auth).
import OpenAI from "openai";
import { ratelimit } from "../../../lib/ratelimit";

const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

export async function POST(req: Request) {
  await ratelimit.limit("chat");
  const body = await req.json();
  const reply = await client.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: "static prompt" }],
  });
  return Response.json(reply);
}
