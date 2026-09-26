// Safe: the Next.js JSON-LD idiom, dangerouslySetInnerHTML fed by
// JSON.stringify(...) of a known object, never raw markup. Must not fire
// injection.dangerous_html.
export function ProductJsonLd({ jsonLd }: { jsonLd: Record<string, unknown> }) {
  return <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }} />;
}
