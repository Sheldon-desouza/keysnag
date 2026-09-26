// INTENTIONALLY INSECURE FIXTURE — never real
import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY as string);

export async function chargeOrder(orderId: string) {
  const priceForOrder = await lookUpServerSidePrice(orderId);
  // No idempotency option here: a retried request creates a second, duplicate charge.
  return stripe.charges.create({
    amount: priceForOrder,
    currency: "usd",
    source: "tok_visa",
  });
}

async function lookUpServerSidePrice(_orderId: string): Promise<number> {
  return 2500;
}
