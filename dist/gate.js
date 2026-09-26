const ORDER = ["info", "low", "medium", "high", "critical"];
/** Numeric rank so severities can be compared. Higher = worse. */
export function rank(s) {
    return ORDER.indexOf(s);
}
export const SEVERITIES = ORDER;
/**
 * The process exit code for a scan.
 *  0  = nothing at or above the fail-on threshold (push may proceed)
 *  2  = at least one finding at or above the threshold (block the push)
 * failOn === "off" never blocks (warn-only).
 */
export function exitCodeForFindings(results, failOn) {
    if (failOn === "off")
        return 0;
    const threshold = rank(failOn);
    const findings = results.flatMap((r) => r.findings);
    return findings.some((f) => rank(f.severity) >= threshold) ? 2 : 0;
}
/** One-line summary of what crossed the threshold, for the hook's stderr. */
export function blockSummary(results, failOn) {
    if (failOn === "off")
        return "";
    const threshold = rank(failOn);
    const blocking = results.flatMap((r) => r.findings).filter((f) => rank(f.severity) >= threshold);
    if (blocking.length === 0)
        return "";
    const bySev = new Map();
    for (const f of blocking)
        bySev.set(f.severity, (bySev.get(f.severity) ?? 0) + 1);
    const parts = [...bySev.entries()].sort((a, b) => rank(b[0]) - rank(a[0])).map(([s, n]) => `${n} ${s}`);
    return `keysnag blocked: ${parts.join(", ")} at or above "${failOn}".`;
}
