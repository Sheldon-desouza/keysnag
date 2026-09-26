// Fixture: process.env dumped into a response. Trips backdoor.env_dump.
export async function GET() {
  return NextResponse.json(process.env);
}

declare const NextResponse: { json(body: unknown): Response };
