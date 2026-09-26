// SAFE FIXTURE — none of the config check's rules should fire on this file.
import { createHash } from "node:crypto";
import { randomUUID } from "node:crypto";
import jwt from "jsonwebtoken";
import { cookies } from "next/headers";

// The Supabase anon key is public by design: safe to ship as NEXT_PUBLIC_.
// NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYW5vbiIsImlzcyI6InN1cGFiYXNlIiwicmVmIjoiZGVtbyJ9.ZmFrZXNpZ25hdHVyZWZha2VzaWduYXR1cmVmYWtlc2ln

export function hashPassword(password: string): string {
  return createHash("sha256").update(password + randomUUID()).digest("hex");
}

export function generateToken(): string {
  return randomUUID();
}

export function signSession(userId: string) {
  return jwt.sign({ userId }, process.env.JWT_SECRET as string);
}

export async function setSessionCookie(sessionId: string) {
  cookies().set("session_id", sessionId, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
  });
}
