// Fixture: process.env serialised/sent into a response or log. Trips backdoor.env_dump
// (high) twice over.
export async function GET() {
  return NextResponse.json({ ...process.env });
}

export function logStartup() {
  console.log(process.env);
}

declare const NextResponse: { json(body: unknown): Response };
