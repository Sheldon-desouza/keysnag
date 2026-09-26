// Fixture: real-world legitimate third-party integrations. None of these are exfil/tunnel
// hosts; must produce zero findings from backdoor.suspicious_outbound.
export async function callFal(prompt: string) {
  return fetch("https://fal.run/fal-ai/flux-pro", {
    method: "POST",
    body: JSON.stringify({ prompt }),
  });
}

export async function callPerplexity(query: string) {
  return fetch("https://api.perplexity.ai/chat/completions", {
    method: "POST",
    body: JSON.stringify({ query }),
  });
}

export async function refreshAmazonToken(refreshToken: string) {
  return fetch("https://api.amazon.com/auth/o2/token", {
    method: "POST",
    body: JSON.stringify({ refresh_token: refreshToken }),
  });
}
