// INTENTIONALLY INSECURE FIXTURE — never real
// app/api/webhook/route.ts style handler that never verifies the Stripe signature.
import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY as string);

export async function POST(request: Request) {
  // No stripe.webhooks.constructEvent call: a forged POST is trusted as-is.
  const event = await request.json();
  if (event.type === "checkout.session.completed") {
    // ... mark the order paid
  }
  return new Response("ok");
}
