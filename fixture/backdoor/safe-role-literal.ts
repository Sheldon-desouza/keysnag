// Fixture: real-world role-literal discriminated-union checks. These are NOT backdoors
// ("role" is no longer a matched identifier); must produce zero findings.
export function lastUserMessage(messages: { role: string; content: string }[]) {
  return messages.filter((m) => m.role === "user");
}

export function performanceCampaign(plan: { campaigns: { role: string }[] }) {
  return plan.campaigns.find((c) => c.role === "performance");
}
