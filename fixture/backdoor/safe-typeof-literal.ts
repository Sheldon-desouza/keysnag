// Regression fixture (LEDGER item 13, backdoor.ts bullet b): typeof-guarded input
// validation and an empty-string not-set check are not hardcoded bypasses. Must
// NOT fire backdoor.literal_bypass.
export function validateApiKey(apiKey: unknown) {
  if (typeof apiKey === "string") {
    return apiKey.length > 0;
  }
  return false;
}

export function hasToken(token: string) {
  if (token === "") {
    return false;
  }
  return true;
}
