// SAFE FIXTURE — this lib file itself must never trip payments.webhook_unverified (fix G:
// only ROUTE handlers are flagged, never the lib file that does the verifying), even though
// it contains createHmac and timingSafeEqual right next to the word "webhook".
import { createHmac, timingSafeEqual } from "node:crypto";

export default function verifyShopifyWebhook(rawBody: string, hmacHeader: string): boolean {
  const digest = createHmac("sha256", process.env.SHOPIFY_WEBHOOK_SECRET as string)
    .update(rawBody, "utf8")
    .digest("base64");
  const expected = Buffer.from(digest);
  const received = Buffer.from(hmacHeader, "base64");
  return expected.length === received.length && timingSafeEqual(expected, received);
}
