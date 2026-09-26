// SAFE FIXTURE — none of the payments check's rules should fire on this file.
import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY as string);

// A verified webhook: signature is checked before anything else runs.
export async function POST(request: Request) {
  const rawBody = await request.text();
  const signature = request.headers.get("stripe-signature") as string;
  const event = stripe.webhooks.constructEvent(
    rawBody,
    signature,
    process.env.STRIPE_WEBHOOK_SECRET as string,
  );

  if (event.type === "checkout.session.completed") {
    // ... mark the order paid
  }
  return new Response("ok");
}

// A server-side price lookup, never trusting a client-supplied amount, with an
// idempotency key so retries can't double-charge.
export async function chargeOrder(orderId: string) {
  const priceForOrder = await lookUpServerSidePrice(orderId);
  return stripe.charges.create(
    { amount: priceForOrder, currency: "usd", source: "tok_visa" },
    { idempotencyKey: orderId },
  );
}

async function lookUpServerSidePrice(_orderId: string): Promise<number> {
  return 2500;
}
