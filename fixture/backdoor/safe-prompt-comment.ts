// Fixture: comments and docstrings that mention "system prompt" but contain no attack
// phrase inside a string literal; must produce zero findings from
// backdoor.prompt_injection_artifact.

// 5. Build system prompt (brand compliance, tone, guardrails)
export function buildSystemPrompt(brand: string) {
  /**
   * The returned string is injected into the assistant's system prompt before
   * every completion call.
   */
  return `You are the brand voice assistant for ${brand}.`;
}
