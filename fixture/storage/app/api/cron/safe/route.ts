// Fixture: cron route that DOES check a shared secret. Should be clean.
export async function GET(req: Request) {
  const provided = req.headers.get("authorization");
  if (provided !== `Bearer ${process.env.CRON_SECRET}`) {
    return new Response("unauthorized", { status: 401 });
  }
  await runNightlySync();
  return new Response("ok");
}

async function runNightlySync() {
  // pretend work
}
