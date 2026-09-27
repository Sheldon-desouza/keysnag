// Regression fixture: a static page
// rendering JSON-LD structured data, no LLM anywhere in the file. Must NOT trip
// ai.unsafe_output_render: __html: JSON.stringify(...) is the standard Next.js
// JSON-LD idiom, not an LLM output render.
export function LandingPage({ jsonLd }: { jsonLd: Record<string, unknown> }) {
  return (
    <>
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }} />
      <h1>Welcome</h1>
    </>
  );
}
