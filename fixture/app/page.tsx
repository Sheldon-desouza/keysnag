// INTENTIONALLY INSECURE FIXTURE — never real
// Hardcoded API keys in a client component: all three end up in the browser
// bundle. vibeguard's `secrets` check must catch each pattern.
"use client";

// Fake Stripe secret key (sk_test_ + 24 chars) — never a live key.
const STRIPE_SECRET_KEY = "sk_test_abcdEFGH12345678ijkl";

// Fake OpenAI key (sk- + 40 chars) — never a live key.
const OPENAI_API_KEY = "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcd";

export default function Home() {
  return (
    <main>
      <h1>vibeguard fixture — deliberately insecure demo</h1>
      <p>Do not deploy this app. See fixture/README.md.</p>
    </main>
  );
}
