// SAFE FIXTURE — this lib file itself must never trip payments.webhook_unverified (fix G:
// only ROUTE handlers are flagged, never the lib file that does the verifying).
import { createHmac, timingSafeEqual } from "node:crypto";

export function verifyTiktokSignature(rawBody: string, signatureHeader: string): boolean {
  const digest = createHmac("sha256", process.env.TIKTOK_WEBHOOK_SECRET as string)
    .update(rawBody, "utf8")
    .digest("hex");
  const expected = Buffer.from(digest);
  const received = Buffer.from(signatureHeader);
  return expected.length === received.length && timingSafeEqual(expected, received);
}
