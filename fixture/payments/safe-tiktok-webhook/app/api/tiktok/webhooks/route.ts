// SAFE FIXTURE — verifies via a sibling lib import; must NOT fire payments.webhook_unverified
// (fix G: importing a verify*Signature helper, plus the x-tiktok-signature header compare,
// are both verification signals).
import { verifyTiktokSignature } from "../../../../../lib/tiktok/verify";

export async function POST(request: Request) {
  const rawBody = await request.text();
  const signatureHeader = request.headers.get("x-tiktok-signature") ?? "";
  if (!verifyTiktokSignature(rawBody, signatureHeader)) {
    return new Response("invalid signature", { status: 401 });
  }
  const event = JSON.parse(rawBody);
  if (event.type === "order_status_change") {
    // ... mark the order paid
  }
  return new Response("ok");
}
