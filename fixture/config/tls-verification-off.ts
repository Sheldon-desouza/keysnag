// INTENTIONALLY INSECURE FIXTURE — never real
import https from "node:https";

// Disables TLS certificate verification: accepts any forged certificate.
const agent = new https.Agent({ rejectUnauthorized: false });

export async function fetchInsecurely(url: string) {
  return fetch(url, { agent } as never);
}
