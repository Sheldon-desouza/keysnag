// Fixture: LLM route with auth + rate limit but a raw user prompt (isolates
// ai.raw_user_prompt).
import OpenAI from "openai";
import { getServerSession } from "next-auth";
import { ratelimit } from "../../../lib/ratelimit";

const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

export async function POST(req: Request) {
  const session = await getServerSession();
  if (!session) return new Response("unauthorized", { status: 401 });
  await ratelimit.limit(session.user.id);
  const body = await req.json();
  const reply = await client.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: body.message }],
  });
  return Response.json(reply);
}
