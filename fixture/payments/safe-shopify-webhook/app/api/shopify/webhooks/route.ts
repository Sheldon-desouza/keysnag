// SAFE FIXTURE — verifies via a sibling lib import; must NOT fire payments.webhook_unverified
// (fix G: importing a verify*Webhook helper is a verification signal).
import verifyShopifyWebhook from "../../../../../lib/shopify/verify";

export async function POST(request: Request) {
  const rawBody = await request.text();
  const hmacHeader = request.headers.get("x-shopify-hmac-sha256") ?? "";
  if (!verifyShopifyWebhook(rawBody, hmacHeader)) {
    return new Response("invalid signature", { status: 401 });
  }
  const event = JSON.parse(rawBody);
  if (event.type === "orders/paid") {
    // ... mark the order paid
  }
  return new Response("ok");
}
