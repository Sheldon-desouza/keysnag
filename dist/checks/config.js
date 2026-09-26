// config: repo-static checks over insecure defaults and misconfiguration (T8/T9 in the
// threat model): secrets leaking through NEXT_PUBLIC_*, service_role reachable from client
// code, TLS verification disabled, prod source maps, permissive CORS, insecure cookies,
// weak randomness/hashing, hardcoded JWT secrets, and debug flags left on.
// Reuses the getScanFiles/isClientShipped-style helpers and finding shape from secrets.ts.
import { readFile, stat, readdir } from "node:fs/promises";
import { join, relative, extname } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { maskSecret } from "../types.js";
const pexec = promisify(execFile);
const SKIP_DIRS = new Set(["node_modules", ".git", "dist", ".next", "build", ".claude", ".vercel", "coverage", ".turbo", "out"]);
const SKIP_EXTS = new Set([
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".woff", ".woff2",
    ".ttf", ".eot", ".pdf", ".zip", ".gz", ".tgz", ".mp4", ".mov", ".mp3",
    ".wasm", ".node", ".lock", ".map",
]);
const MAX_FILE_BYTES = 2 * 1024 * 1024;
async function walkRepo(root) {
    const results = [];
    async function walk(dir) {
        let entries;
        try {
            entries = await readdir(dir, { withFileTypes: true });
        }
        catch {
            return;
        }
        for (const entry of entries) {
            if (entry.isDirectory()) {
                if (SKIP_DIRS.has(entry.name))
                    continue;
                await walk(join(dir, entry.name));
            }
            else if (entry.isFile()) {
                if (SKIP_EXTS.has(extname(entry.name)))
                    continue;
                results.push(join(dir, entry.name));
            }
        }
    }
    await walk(root);
    return results;
}
/** Files to scan: honours ctx.changedFiles when set, else git-tracked/untracked, else a walk. */
async function getScanFiles(repoDir, changedFiles) {
    if (changedFiles && changedFiles.length > 0) {
        return changedFiles.map((f) => join(repoDir, f));
    }
    try {
        const { stdout } = await pexec("git", ["-C", repoDir, "ls-files", "--cached", "--others", "--exclude-standard", "-z"], { maxBuffer: 128 * 1024 * 1024 });
        const rel = stdout.split("\u0000").filter(Boolean);
        if (rel.length === 0)
            return await walkRepo(repoDir);
        return rel.filter((r) => !SKIP_EXTS.has(extname(r))).map((r) => join(repoDir, r));
    }
    catch {
        return await walkRepo(repoDir);
    }
}
function isEnvFile(relPath) {
    const base = relPath.replace(/\\/g, "/").split("/").pop() ?? "";
    return base === ".env" || base === ".env.local" || /^\.env\./.test(base);
}
/** Source-code files, plus the specific config filenames these rules need: skip markdown/docs
 * (vulnerable EXAMPLE snippets) and keysnag's own skill docs. */
const SOURCE_EXTS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts"]);
const DOC_EXTS = new Set([".md", ".mdx", ".txt"]);
function isScannableConfigFile(relPath) {
    const norm = relPath.replace(/\\/g, "/");
    if (norm === ".claude" || norm.startsWith(".claude/") || norm.includes("/.claude/"))
        return false;
    if (norm === "docs" || norm.startsWith("docs/") || norm.includes("/docs/"))
        return false;
    const ext = extname(norm);
    if (DOC_EXTS.has(ext))
        return false;
    if (isEnvFile(norm) || ext === ".env")
        return true;
    const base = norm.split("/").pop() ?? "";
    if (/^next\.config\.(js|ts|mjs|cjs)$/.test(base))
        return true;
    if (base === "vercel.json")
        return true;
    return SOURCE_EXTS.has(ext);
}
/** "use client" directive, or anything shipped verbatim from public/. */
function isClientComponent(relPath, text) {
    const norm = relPath.replace(/\\/g, "/");
    if (norm.includes("/public/") || norm.startsWith("public/"))
        return true;
    return /^\s*["']use client["'];?\s*$/m.test(text.split("\n").slice(0, 5).join("\n"));
}
/** Same value-shape heuristic as secrets.ts: high entropy, character-class diversity, not a slug/URL/MIME type. */
function looksLikeSecretValue(v) {
    if (v.length < 20)
        return false;
    if (/^[a-z0-9]+([._\-/:][a-z0-9]+)*$/.test(v))
        return false;
    if (/^(https?:\/\/|\.?\/)/.test(v))
        return false;
    if (/^[a-z]+\/[a-z0-9][a-z0-9.+_-]*$/i.test(v))
        return false;
    const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((re) => re.test(v)).length;
    if (classes < 2)
        return false;
    return shannonEntropy(v) >= 3.6;
}
function shannonEntropy(s) {
    const counts = new Map();
    for (const ch of s)
        counts.set(ch, (counts.get(ch) ?? 0) + 1);
    let entropy = 0;
    for (const count of counts.values()) {
        const p = count / s.length;
        entropy -= p * Math.log2(p);
    }
    return entropy;
}
function decodeJwtPayload(token) {
    const parts = token.split(".");
    if (parts.length !== 3)
        return null;
    try {
        let b64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
        while (b64.length % 4 !== 0)
            b64 += "=";
        return JSON.parse(Buffer.from(b64, "base64").toString("utf8"));
    }
    catch {
        return null;
    }
}
const NEXT_PUBLIC_ASSIGN = /\b(NEXT_PUBLIC_[A-Z0-9_]+)\s*[:=]\s*["'`]?([^"'`\n,}]+)["'`]?/g;
const JWT_SHAPE = /^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
function rule_publicEnvSecret(relPath, text, findings) {
    const lines = text.split("\n");
    for (let i = 0; i < lines.length; i++) {
        NEXT_PUBLIC_ASSIGN.lastIndex = 0;
        for (const m of lines[i].matchAll(NEXT_PUBLIC_ASSIGN)) {
            const [, name, rawValue] = m;
            const value = rawValue.trim();
            const nameSecretShaped = /SECRET|SERVICE_ROLE|PRIVATE|TOKEN|PASSWORD/i.test(name);
            let valueSecretShaped = false;
            if (JWT_SHAPE.test(value)) {
                const payload = decodeJwtPayload(value);
                valueSecretShaped = payload?.["role"] === "service_role";
            }
            else if (!/^\$\{|^process\.env/.test(value)) {
                valueSecretShaped = looksLikeSecretValue(value);
            }
            if (!nameSecretShaped && !valueSecretShaped)
                continue;
            findings.push({
                id: "config.public_env_secret",
                check: "config",
                severity: valueSecretShaped ? "critical" : "high",
                title: `NEXT_PUBLIC_ variable "${name}" looks secret-shaped`,
                detail: valueSecretShaped
                    ? `${name} is a NEXT_PUBLIC_* variable, which Next.js inlines into every client bundle, and its value looks like a real credential.`
                    : `${name} is a NEXT_PUBLIC_* variable whose name suggests a secret (SECRET/SERVICE_ROLE/PRIVATE/TOKEN/PASSWORD). Anything with the NEXT_PUBLIC_ prefix ships to every visitor's browser, so if this ever holds a real credential it is already exposed.`,
                location: `${relPath}:${i + 1}`,
                evidence: maskSecret(value),
                fix: `Rename ${name} without the NEXT_PUBLIC_ prefix and read it only in server code, or confirm this is a genuinely public value (like an anon key) and not a secret.`,
            });
        }
    }
}
// Actual USE only, not a bare name string (e.g. a UI label listing env var names):
// process.env.SUPABASE_SERVICE_ROLE_KEY / process.env.*SERVICE_ROLE*, or that value passed
// into createClient(...), or a JWT literal whose decoded payload role is service_role.
const SERVICE_ROLE_ENV_USE = /process\.env\.[A-Z0-9_]*SERVICE_ROLE[A-Z0-9_]*\b/;
const CREATE_CLIENT_SERVICE_ROLE = /createClient\s*\([^)]*\b[A-Za-z0-9_]*[Ss]ervice_?[Rr]ole[A-Za-z0-9_]*\b[^)]*\)/;
const JWT_LITERAL = /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/;
function isServiceRoleUse(line) {
    if (SERVICE_ROLE_ENV_USE.test(line))
        return true;
    if (CREATE_CLIENT_SERVICE_ROLE.test(line))
        return true;
    const jwt = line.match(JWT_LITERAL);
    if (jwt) {
        const payload = decodeJwtPayload(jwt[0]);
        if (payload?.["role"] === "service_role")
            return true;
    }
    return false;
}
function rule_serviceRoleInClient(relPath, text, findings) {
    if (!isClientComponent(relPath, text))
        return;
    const lines = text.split("\n");
    for (let i = 0; i < lines.length; i++) {
        if (isServiceRoleUse(lines[i])) {
            findings.push({
                id: "config.service_role_in_client",
                check: "config",
                severity: "high",
                title: "service_role referenced in client-reachable code",
                detail: "This file is a client component (\"use client\") or lives under public/, and it references the Supabase service_role key or key name. Anything in a client component is bundled and shipped to every visitor's browser.",
                location: `${relPath}:${i + 1}`,
                fix: "Move any service_role usage into server-only code (a route handler, server action, or server component with no \"use client\"), never a client component.",
            });
        }
    }
}
const TLS_OFF = /NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*['"]?0['"]?|rejectUnauthorized\s*:\s*false|strictSSL\s*:\s*false/;
function rule_tlsVerificationOff(relPath, text, findings) {
    const lines = text.split("\n");
    for (let i = 0; i < lines.length; i++) {
        if (TLS_OFF.test(lines[i])) {
            findings.push({
                id: "config.tls_verification_off",
                check: "config",
                severity: "critical",
                title: "TLS certificate verification is disabled",
                detail: "This disables TLS/SSL certificate verification, so the app will silently accept a forged certificate from a machine-in-the-middle attacker on any outbound HTTPS connection.",
                location: `${relPath}:${i + 1}`,
                fix: "Remove NODE_TLS_REJECT_UNAUTHORIZED=0 / rejectUnauthorized:false / strictSSL:false. If a self-signed cert is needed for local dev, scope it to development only and never ship it.",
            });
        }
    }
}
function rule_sourceMapsProd(relPath, text, findings) {
    if (!/next\.config\.(js|ts|mjs|cjs)$/.test(relPath.replace(/\\/g, "/")))
        return;
    const lines = text.split("\n");
    for (let i = 0; i < lines.length; i++) {
        if (/productionBrowserSourceMaps\s*:\s*true/.test(lines[i])) {
            findings.push({
                id: "config.source_maps_prod",
                check: "config",
                severity: "high",
                title: "Production browser source maps are enabled",
                detail: "productionBrowserSourceMaps: true ships readable source maps for the client bundle in production, making it trivial to read your app's original source (and anything embedded in it) from the browser.",
                location: `${relPath}:${i + 1}`,
                fix: "Remove productionBrowserSourceMaps: true (or set it to false), and upload source maps privately to your error-tracking tool if you need them.",
            });
        }
    }
}
const CORS_WILDCARD = /Access-Control-Allow-Origin['",:\s]*\*|origin\s*:\s*['"]\*['"]/;
const CORS_CREDENTIALS = /Access-Control-Allow-Credentials['",:\s]*true|credentials\s*:\s*true/;
function rule_corsWildcardCredentials(relPath, text, findings) {
    if (!CORS_WILDCARD.test(text) || !CORS_CREDENTIALS.test(text))
        return;
    const lines = text.split("\n");
    const line = lines.findIndex((l) => CORS_WILDCARD.test(l)) + 1 || 1;
    findings.push({
        id: "config.cors_wildcard_credentials",
        check: "config",
        severity: "high",
        title: "CORS allows any origin together with credentials",
        detail: "This file sets Access-Control-Allow-Origin to * while also allowing credentials. Browsers actually forbid this combination on real requests, but where a proxy or framework enforces it anyway it lets any website read authenticated responses on a user's behalf.",
        location: `${relPath}:${line}`,
        fix: "Reflect a specific allow-listed origin instead of *, and only set Access-Control-Allow-Credentials: true for that allow-listed origin.",
    });
}
const COOKIE_SET = /cookies\(\)\.set\(|res\.cookie\(|['"]Set-Cookie['"]/;
function rule_insecureCookie(relPath, text, findings) {
    if (isClientComponent(relPath, text))
        return; // cookies are set server-side
    const lines = text.split("\n");
    for (let i = 0; i < lines.length; i++) {
        if (!COOKIE_SET.test(lines[i]))
            continue;
        const windowText = lines.slice(i, Math.min(lines.length, i + 6)).join("\n");
        const hasHttpOnly = /httpOnly\s*:\s*true|HttpOnly/i.test(windowText);
        const hasSecure = /secure\s*:\s*true|;\s*Secure/i.test(windowText);
        const hasSameSite = /sameSite\s*:|SameSite=/i.test(windowText);
        if (hasHttpOnly && hasSecure && hasSameSite)
            continue;
        const missing = [!hasHttpOnly && "httpOnly", !hasSecure && "secure", !hasSameSite && "sameSite"]
            .filter(Boolean)
            .join(", ");
        findings.push({
            id: "config.insecure_cookie",
            check: "config",
            severity: "high",
            title: "cookie set without httpOnly/secure/sameSite",
            detail: `A cookie is set here without: ${missing}. Missing httpOnly lets client-side JS (and any XSS) read it; missing secure lets it travel over plain HTTP; missing sameSite makes it usable in cross-site requests.`,
            location: `${relPath}:${i + 1}`,
            fix: "Set httpOnly: true, secure: true, and an explicit sameSite ('lax' or 'strict') on every cookie the server sets.",
        });
    }
}
const TOKEN_IDENT = /\b(token|secret|password|apiKey|sessionId|nonce)\b/i;
function rule_weakRandomToken(relPath, text, findings) {
    const lines = text.split("\n");
    for (let i = 0; i < lines.length; i++) {
        if (!/Math\.random\(\)/.test(lines[i]))
            continue;
        const start = Math.max(0, i - 3);
        const end = Math.min(lines.length, i + 4);
        const windowText = lines.slice(start, end).join("\n");
        if (!TOKEN_IDENT.test(windowText))
            continue;
        findings.push({
            id: "config.weak_random_token",
            check: "config",
            severity: "high",
            title: "Math.random() used to build a token/secret/id",
            detail: "Math.random() is not cryptographically secure; its output is predictable enough to brute-force or reconstruct, which is unsafe for anything used as a token, session id, password, or nonce.",
            location: `${relPath}:${i + 1}`,
            fix: "Use crypto.randomUUID() or crypto.randomBytes(n).toString('hex') (Node's built-in crypto module) instead of Math.random() for anything security-sensitive.",
        });
    }
}
const WEAK_HASH = /\b(md5|sha1)\s*\(|createHash\(\s*['"](md5|sha1)['"]\s*\)/i;
function rule_weakHashPassword(relPath, text, findings) {
    const lines = text.split("\n");
    for (let i = 0; i < lines.length; i++) {
        if (!WEAK_HASH.test(lines[i]))
            continue;
        const start = Math.max(0, i - 3);
        const end = Math.min(lines.length, i + 4);
        const windowText = lines.slice(start, end).join("\n");
        if (!/password/i.test(windowText))
            continue;
        findings.push({
            id: "config.weak_hash_password",
            check: "config",
            severity: "high",
            title: "MD5/SHA1 used to hash a password",
            detail: "MD5 and SHA1 are fast, unsalted-by-default hashes that are cracked in bulk with commodity hardware and rainbow tables. Neither is safe for password storage.",
            location: `${relPath}:${i + 1}`,
            fix: "Hash passwords with bcrypt, scrypt, or argon2 (all designed to be slow and salted), never md5/sha1.",
        });
    }
}
const JWT_HARDCODED = /jwt\.(?:sign|verify)\(([\s\S]{0,300}?)\)/g;
function rule_hardcodedJwtSecret(relPath, text, findings) {
    JWT_HARDCODED.lastIndex = 0;
    for (const m of text.matchAll(JWT_HARDCODED)) {
        const args = m[1];
        const literalSecret = /,\s*["'`]([^"'`]{6,})["'`]/.exec(args);
        if (!literalSecret)
            continue;
        const before = text.slice(0, m.index ?? 0);
        const line = before.split("\n").length;
        findings.push({
            id: "config.hardcoded_jwt_secret",
            check: "config",
            severity: "high",
            title: "jwt.sign/verify called with a hardcoded secret",
            detail: "The signing/verification secret is a string literal in source rather than an environment variable, so anyone with the source (including in a public repo or a client bundle) can forge or read tokens.",
            location: `${relPath}:${line}`,
            evidence: maskSecret(literalSecret[1]),
            fix: "Load the JWT secret from a server-only environment variable (e.g. process.env.JWT_SECRET), generated with high entropy, and never commit it.",
        });
    }
}
const DEBUG_ON = /\bDEBUG\s*=\s*true\b|\bdebug\s*:\s*true\b/;
function rule_debugOn(relPath, text, findings) {
    const norm = relPath.replace(/\\/g, "/");
    const isProdConfig = isEnvFile(norm) || /next\.config\.|vercel\.json$/.test(norm);
    if (!isProdConfig)
        return;
    if (/\.env\.(development|local)$/.test(norm.split("/").pop() ?? ""))
        return;
    const lines = text.split("\n");
    for (let i = 0; i < lines.length; i++) {
        if (DEBUG_ON.test(lines[i])) {
            findings.push({
                id: "config.debug_on",
                check: "config",
                severity: "medium",
                title: "debug mode left on in production config",
                detail: "DEBUG=true / debug: true is set in a file that looks like production configuration. Debug mode commonly turns on verbose logging, stack traces, and query logs that leak internals to an attacker.",
                location: `${relPath}:${i + 1}`,
                fix: "Turn debug mode off for production (leave it only in .env.development or .env.local), and gate any verbose logging behind NODE_ENV !== 'production'.",
            });
        }
    }
}
const configCheck = {
    name: "config",
    description: "Static checks for insecure defaults and misconfiguration: public secrets, TLS off, prod source maps, permissive CORS, insecure cookies, weak randomness/hashing, hardcoded JWT secrets, debug flags.",
    requires: [],
    async run(ctx) {
        const findings = [];
        const repoDir = ctx.repoDir ?? ".";
        const files = await getScanFiles(repoDir, ctx.changedFiles);
        for (const filePath of files) {
            let info;
            try {
                info = await stat(filePath);
            }
            catch {
                continue;
            }
            if (!info.isFile() || info.size > MAX_FILE_BYTES)
                continue;
            const relPath = relative(repoDir, filePath);
            if (!isScannableConfigFile(relPath))
                continue;
            let text;
            try {
                text = await readFile(filePath, "utf8");
            }
            catch {
                continue;
            }
            if (text.includes("\u0000"))
                continue;
            rule_publicEnvSecret(relPath, text, findings);
            rule_serviceRoleInClient(relPath, text, findings);
            rule_tlsVerificationOff(relPath, text, findings);
            rule_sourceMapsProd(relPath, text, findings);
            rule_corsWildcardCredentials(relPath, text, findings);
            rule_insecureCookie(relPath, text, findings);
            rule_weakRandomToken(relPath, text, findings);
            rule_weakHashPassword(relPath, text, findings);
            rule_hardcodedJwtSecret(relPath, text, findings);
            rule_debugOn(relPath, text, findings);
        }
        ctx.log(`config: scanned ${files.length} file(s), found ${findings.length} finding(s)`);
        return { check: "config", ran: true, findings };
    },
};
export default configCheck;
