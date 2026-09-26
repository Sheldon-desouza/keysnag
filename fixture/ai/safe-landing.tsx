// Regression fixture (LEDGER item 11, ai-endpoints.ts bullet H): a marketing page
// that renders pre-authored HTML with no LLM SDK/import anywhere in the file.
// Must NOT trip ai.unsafe_output_render: there is no LLM call in this file.
export function MarketingSection({ marketingHtml }: { marketingHtml: string }) {
  return <div dangerouslySetInnerHTML={{ __html: marketingHtml }} />;
}
