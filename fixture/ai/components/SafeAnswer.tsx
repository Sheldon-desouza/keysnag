"use client";
// Fixture: LLM output rendered as HTML but sanitised first. Should produce no
// ai.unsafe_output_render finding.
import { marked } from "marked";
import DOMPurify from "dompurify";

export function SafeAnswer({ reply }: { reply: string }) {
  const html = DOMPurify.sanitize(marked(reply));
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
