// keysnag contract. Every check implements Check; the harness consumes CheckResult.
// This file is authoritative. Checks and harness must not redefine these shapes.
/** Helper for checks: mask a secret so evidence never carries a live value. */
export function maskSecret(v) {
    if (v.length <= 12)
        return "****";
    return `${v.slice(0, 4)}…${v.slice(-4)} (${v.length} chars)`;
}
