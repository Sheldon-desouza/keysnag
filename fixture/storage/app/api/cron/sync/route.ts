// Fixture: cron route with no shared-secret check. Trips storage.cron_no_secret.
export async function GET() {
  await runNightlySync();
  return new Response("ok");
}

async function runNightlySync() {
  // pretend work
}
