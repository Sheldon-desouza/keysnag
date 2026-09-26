// Fixture: clean file for the backdoor check. Should produce no findings.
export function checkRole(role: string, allowedRoles: string[]) {
  return allowedRoles.includes(role);
}

export async function reportUsage(payload: unknown) {
  await fetch("https://api.stripe.com/v1/events", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function greeting(name: string) {
  return `Hello, ${name}!`;
}
