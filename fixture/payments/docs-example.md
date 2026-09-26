# Vulnerable example (docs only)

The vibe-security skill shows this as the pattern to flag, not something to run:

```ts
stripe.checkout.sessions.create({
  line_items: [{ price_data: { currency: "usd", unit_amount: req.body.price } }],
});
```

This is a markdown doc, not source: fix A must skip it so it never fires
payments.client_priced_charge.
