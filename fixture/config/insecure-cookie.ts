// INTENTIONALLY INSECURE FIXTURE — never real
import { cookies } from "next/headers";

export async function setSessionCookie(sessionId: string) {
  // No httpOnly, secure, or sameSite: readable by client JS (and any XSS),
  // sent over plain HTTP, and usable in cross-site requests.
  cookies().set("session_id", sessionId, { path: "/" });
}
