// INTENTIONALLY INSECURE FIXTURE — never real
import { createHash } from "node:crypto";

export function hashPassword(password: string): string {
  // MD5 is fast and unsalted: crackable in bulk with commodity hardware.
  return createHash("md5").update(password).digest("hex");
}
