"use client";
// Fixture: LLM output rendered as HTML with no sanitiser. Trips ai.unsafe_output_render.
import { marked } from "marked";

export function UnsafeAnswer({ reply }: { reply: string }) {
  const html = marked(reply);
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
