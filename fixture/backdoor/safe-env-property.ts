// Fixture: a single named env property read passed into JSON.stringify, the real
// pattern from a background job. Reading one key, not the whole object, is not a
// dump. Must produce zero findings from backdoor.env_dump.
export async function scheduleContinuation(sessionId: string, continueUrl: string) {
  return fetch(continueUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ sessionId, key: process.env.INTERNAL_JOB_KEY }),
  });
}
