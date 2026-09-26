"use client";
// Fixture: LLM SDK called directly from a client component. Trips ai.llm_call_in_client.
import OpenAI from "openai";

const client = new OpenAI({ apiKey: "sk-fake-not-a-real-key-0000000000" });

export function ChatWidget() {
  async function ask(question: string) {
    return client.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: question }],
    });
  }
  return null;
}
