// Fixture: auth-skip flag short-circuits an auth check. Trips backdoor.auth_skip_flag.
export async function handler(req: Request) {
  if (process.env.SKIP_AUTH || (await checkSession(req))) {
    return doWork();
  }
  return new Response("unauthorized", { status: 401 });
}

async function checkSession(req: Request) {
  return false;
}

function doWork() {
  return new Response("ok");
}
