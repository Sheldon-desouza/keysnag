// Fixture: LLM output rendered as HTML with no sanitiser. Trips ai.unsafe_output_render.
// Calls the LLM (messages.create) in this same file, satisfying the rule's
// same-file LLM-call requirement.
import { marked } from "marked";
import Anthropic from "@anthropic-ai/sdk";

const anthropic = new Anthropic();

export async function UnsafeAnswer({ question }: { question: string }) {
  const response = await anthropic.messages.create({
    model: "claude-3-5-sonnet-latest",
    max_tokens: 512,
    messages: [{ role: "user", content: question }],
  });
  const reply = response.content[0].type === "text" ? response.content[0].text : "";
  const html = marked(reply);
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
