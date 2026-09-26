// Regression fixture (LEDGER item 13e / spec 11E): a file under a /components/
// directory calling fetch(userUrl) where userUrl comes from the request body.
// Must NOT fire injection.ssrf: anything under /components/ is treated as a
// same-origin UI surface for this rule, same as "use client".
export async function LinkPreviewWidget({ body }: { body: { url: string } }) {
  const userUrl = body.url;
  const res = await fetch(userUrl);
  return res.text();
}
