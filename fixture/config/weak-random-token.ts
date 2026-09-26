// INTENTIONALLY INSECURE FIXTURE — never real

export function generateSessionToken(): string {
  // Math.random() is not cryptographically secure: predictable, brute-forceable.
  const token = Math.random().toString(36).slice(2);
  return token;
}
