// INTENTIONALLY INSECURE FIXTURE — never real
import jwt from "jsonwebtoken";

export function signSession(userId: string) {
  // The secret is a string literal in source, not an env var: anyone with the
  // source (including a public repo or a client bundle) can forge tokens.
  return jwt.sign({ userId }, "my-super-secret-signing-key-12345");
}
