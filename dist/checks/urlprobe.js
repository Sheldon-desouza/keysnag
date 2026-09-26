const TIMEOUT_MS = 10_000;
const USER_AGENT = "keysnag-scan";
function fetchOpts() {
    return {
        signal: AbortSignal.timeout(TIMEOUT_MS),
        headers: { "User-Agent": USER_AGENT },
        redirect: "manual",
    };
}
async function safeGet(url) {
    try {
        const res = await fetch(url, fetchOpts());
        const text = await res.text().catch(() => "");
        return { status: res.status, text };
    }
    catch {
        return null;
    }
}
const SENSITIVE_PATHS = [
    {
        path: "/.env",
        id: "urlprobe.env_exposed",
        title: ".env file is publicly reachable",
        isSensitive: (status, text) => status === 200 && (text.includes("=") && text.length > 0),
        fix: "Remove .env from the public/served directory, add it to your server's deny rules or .gitignore, and rotate every secret it contained.",
    },
    {
        path: "/.env.local",
        id: "urlprobe.env_local_exposed",
        title: ".env.local file is publicly reachable",
        isSensitive: (status, text) => status === 200 && text.includes("=") && text.length > 0,
        fix: "Remove .env.local from the public/served directory and rotate every secret it contained.",
    },
    {
        path: "/.git/HEAD",
        id: "urlprobe.git_head_exposed",
        title: ".git/HEAD is publicly reachable",
        isSensitive: (status, text) => status === 200 && /^ref:|^[0-9a-f]{40}/.test(text.trim()),
        fix: "Block access to /.git/ at the web server or hosting config level; a public .git directory can leak your entire source history.",
    },
    {
        path: "/.git/config",
        id: "urlprobe.git_config_exposed",
        title: ".git/config is publicly reachable",
        isSensitive: (status, text) => status === 200 && text.includes("[core]"),
        fix: "Block access to /.git/ at the web server or hosting config level; the git config can leak remote URLs and sometimes credentials.",
    },
    {
        path: "/server.js.map",
        id: "urlprobe.sourcemap_exposed",
        title: "Server source map is publicly reachable",
        isSensitive: (status, text) => status === 200 && text.includes('"sources"'),
        fix: "Disable production source map generation for server bundles, or block .map files from being served.",
    },
    {
        path: "/config.json",
        id: "urlprobe.config_json_exposed",
        title: "config.json is publicly reachable",
        isSensitive: (status, text) => status === 200 && text.trim().startsWith("{"),
        fix: "Remove config.json from the publicly served directory, or confirm it contains no secrets or internal configuration.",
    },
];
async function probeSensitivePaths(origin) {
    const findings = [];
    for (const def of SENSITIVE_PATHS) {
        const result = await safeGet(origin + def.path);
        if (result && def.isSensitive(result.status, result.text)) {
            findings.push({
                id: def.id,
                check: "urlprobe",
                severity: "critical",
                title: def.title,
                detail: `A GET request to ${def.path} returned 200 with what looks like sensitive content.`,
                location: origin + def.path,
                fix: def.fix,
            });
        }
    }
    return findings;
}
/** Find *.map files referenced by the main page's script/link tags. */
async function probeReferencedSourceMaps(origin, html) {
    const findings = [];
    const jsUrls = new Set();
    for (const match of html.matchAll(/<script[^>]+src=["']([^"']+)["']/g)) {
        jsUrls.add(match[1]);
    }
    let checked = 0;
    for (const src of jsUrls) {
        if (checked >= 15)
            break; // stay bounded
        let abs;
        try {
            abs = new URL(src, origin);
        }
        catch {
            continue;
        }
        if (abs.origin !== origin)
            continue;
        const mapUrl = abs.toString() + ".map";
        checked++;
        const result = await safeGet(mapUrl);
        if (result && result.status === 200 && result.text.includes('"sources"')) {
            findings.push({
                id: "urlprobe.sourcemap_exposed",
                check: "urlprobe",
                severity: "medium",
                title: "JS source map is publicly reachable",
                detail: `A source map for a shipped bundle is publicly reachable, which can expose original (unminified) source code.`,
                location: mapUrl,
                fix: "Disable production source map uploads to the public build output, or restrict access to .map files.",
            });
        }
    }
    return findings;
}
const ADMIN_PATHS = ["/admin", "/dashboard", "/api/admin"];
function looksLikeLogin(text) {
    return /sign.?in|log.?in|password|unauthori[sz]ed|forbidden|401|403/i.test(text.slice(0, 4000));
}
async function probeAdminRoutes(origin) {
    const findings = [];
    for (const path of ADMIN_PATHS) {
        const result = await safeGet(origin + path);
        if (!result)
            continue;
        if (result.status === 200 && result.text.length > 0 && !looksLikeLogin(result.text)) {
            findings.push({
                id: "urlprobe.admin_route_reachable",
                check: "urlprobe",
                severity: "critical",
                title: "Admin route reachable while logged out",
                detail: `${path} returned 200 with content that does not look like a login page, while unauthenticated. This may expose admin functionality to anyone.`,
                location: origin + path,
                fix: "Add server-side auth middleware that redirects or 401s unauthenticated requests to this route before any admin content is rendered.",
            });
        }
    }
    return findings;
}
const SECURITY_HEADERS = [
    { header: "Strict-Transport-Security", isPresent: (h) => h.has("strict-transport-security") },
    { header: "X-Content-Type-Options", isPresent: (h) => h.has("x-content-type-options") },
    {
        header: "X-Frame-Options or CSP frame-ancestors",
        isPresent: (h) => h.has("x-frame-options") || /frame-ancestors/i.test(h.get("content-security-policy") ?? ""),
    },
    { header: "Content-Security-Policy", isPresent: (h) => h.has("content-security-policy") },
];
async function probeSecurityHeaders(siteUrl) {
    let res;
    try {
        res = await fetch(siteUrl, fetchOpts());
    }
    catch {
        return [];
    }
    const missing = SECURITY_HEADERS.filter((c) => !c.isPresent(res.headers)).map((c) => c.header);
    if (missing.length === 0)
        return [];
    return [
        {
            id: "urlprobe.missing_security_headers",
            check: "urlprobe",
            severity: missing.length >= 3 ? "medium" : "low",
            title: "Missing security headers on main page",
            detail: `The main page response is missing: ${missing.join(", ")}. These headers harden the site against clickjacking, MIME sniffing, and downgrade attacks.`,
            location: siteUrl,
            fix: "Add the missing headers (e.g. via Next.js headers() config or a reverse proxy): Strict-Transport-Security, X-Content-Type-Options: nosniff, a frame-ancestors/X-Frame-Options policy, and a Content-Security-Policy.",
        },
    ];
}
/**
 * Discover a REAL auth endpoint on the app origin. Compares each candidate to a
 * control request to a path that certainly does not exist: if the candidate
 * returns the same status as the control, the response is a framework default
 * (a blanket middleware deny or a catch-all), not a distinct endpoint, so we do
 * not report on it. This stops keysnag calling a default-deny an unprotected
 * endpoint. Only API paths are considered; a login PAGE (GET 200) is not a
 * credential endpoint worth flood-probing.
 */
async function discoverAuthPath(origin) {
    const control = await safeGet(origin + "/api/keysnag-control-" + Math.random().toString(36).slice(2, 10));
    const controlStatus = control?.status ?? 0;
    const candidates = ["/api/auth", "/api/login", "/api/signin", "/api/session"];
    for (const path of candidates) {
        const result = await safeGet(origin + path);
        if (!result)
            continue;
        if (result.status === 404)
            continue;
        if (result.status === controlStatus)
            continue; // same as a nonexistent path => not a real endpoint
        return path;
    }
    return null;
}
async function probeRateLimit(origin) {
    const path = await discoverAuthPath(origin);
    if (!path)
        return []; // nothing discoverable, nothing to report
    const statuses = [];
    for (let i = 0; i < 12; i++) {
        const result = await safeGet(origin + path);
        statuses.push(result?.status ?? 0);
        if (i < 11)
            await new Promise((r) => setTimeout(r, 200));
    }
    const blocked = statuses.some((s) => s === 429 || s === 403);
    if (blocked)
        return [];
    return [
        {
            id: "urlprobe.no_rate_limiting",
            check: "urlprobe",
            severity: "medium",
            title: `No rate limiting observed on ${path}`,
            detail: `Sent 12 sequential requests to ${path}, 200ms apart, and none were throttled (no 429/403). An unthrottled auth endpoint is easier to brute-force. Note: if your app authenticates directly against Supabase/Auth0/Clerk from the browser, the real rate limit lives in that provider's settings, not this route.`,
            location: origin + path,
            fix: "Add rate limiting (e.g. per-IP or per-account token bucket) in front of this endpoint, especially for login/auth flows.",
        },
    ];
}
const urlprobeCheck = {
    name: "urlprobe",
    description: "Probes a live site for exposed source files, reachable admin routes while logged out, missing security headers, and absent rate limiting.",
    requires: ["siteUrl"],
    async run(ctx) {
        if (!ctx.siteUrl) {
            return { check: "urlprobe", ran: false, skippedReason: "siteUrl was not provided", findings: [] };
        }
        const origin = new URL(ctx.siteUrl).origin;
        const findings = [];
        const mainPage = await safeGet(ctx.siteUrl);
        const [sensitive, admin, headers] = await Promise.all([
            probeSensitivePaths(origin),
            probeAdminRoutes(origin),
            probeSecurityHeaders(ctx.siteUrl),
        ]);
        findings.push(...sensitive, ...admin, ...headers);
        if (mainPage) {
            findings.push(...(await probeReferencedSourceMaps(origin, mainPage.text)));
        }
        findings.push(...(await probeRateLimit(origin)));
        ctx.log(`urlprobe: probed ${origin}, found ${findings.length} finding(s)`);
        return { check: "urlprobe", ran: true, findings };
    },
};
export default urlprobeCheck;
