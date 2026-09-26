// Seeded flaw: dangerouslySetInnerHTML fed by a non-literal (a variable holding
// user-submitted comment text). Expected finding: injection.dangerous_html (high).
export function Comment({ body }: { body: string }) {
  return <div dangerouslySetInnerHTML={{ __html: body }} />;
}
