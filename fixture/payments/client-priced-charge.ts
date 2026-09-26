// INTENTIONALLY INSECURE FIXTURE — never real
import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY as string);

export async function POST(request: Request) {
  // amount/currency are trusted from the client: a caller can pay whatever it likes.
  const { amount, currency } = await request.json();

  const paymentIntent = await stripe.paymentIntents.create({
    amount,
    currency,
  });

  return Response.json({ clientSecret: paymentIntent.client_secret });
}
