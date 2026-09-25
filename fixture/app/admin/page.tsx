// INTENTIONALLY INSECURE FIXTURE — never real
// Admin page with no auth guard: any logged-out visitor who knows the URL
// sees admin content. vibeguard's `urlprobe` check must catch this.
export default function AdminPage() {
  return (
    <main>
      <h1>Admin dashboard</h1>
      <p>All users, all orders, all revenue — no login required to view this.</p>
    </main>
  );
}
