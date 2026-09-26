// Fixture: hardcoded literal bypasses. Trips backdoor.literal_bypass (critical for
// password/token/secret, high for a role literal).
export function checkAdminPassword(password: string) {
  if (password === "letmein123") {
    return true;
  }
  return false;
}

export function checkRole(role: string) {
  if (role === "admin") {
    return true;
  }
  return false;
}
