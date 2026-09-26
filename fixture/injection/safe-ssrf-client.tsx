// Safe: a "use client" component calling its own API with a relative URL built
// from a prop's id. This is same-origin, not SSRF, and the file is a client
// component to begin with. Must not fire injection.ssrf.
"use client";

interface ApprovalRequest {
  id: string;
}

export function ApproveButton({ request }: { request: ApprovalRequest }) {
  async function approve() {
    await fetch(`/api/approvals/${request.id}/apply`, { method: "POST" });
  }
  return <button onClick={approve}>Approve</button>;
}
