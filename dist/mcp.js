#!/usr/bin/env node
// keysnag MCP stdio server. Exposes `run_security_check` (the full report) plus one
// `check_<name>` tool per registered check, for a coding agent to call individually.
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { loadContext, loadEnabledChecks } from "./config.js";
import { runChecks } from "./runner.js";
import { renderMarkdown } from "./report.js";
import { checks } from "./checks/index.js";
const server = new McpServer({
    name: "keysnag",
    version: "0.0.0",
});
server.registerTool("run_security_check", {
    description: "Run keysnag's local security checks (secrets, url probe, RLS audit, cross-account access) and return the markdown report. Nothing leaves the machine except requests to the site/database URLs you provide.",
    inputSchema: {
        repoDir: z
            .string()
            .optional()
            .describe("path to the repo to scan, defaults to the current directory"),
        siteUrl: z
            .string()
            .optional()
            .describe("deployed site URL to probe, e.g. https://your-app.vercel.app"),
        checks: z
            .array(z.string())
            .optional()
            .describe("subset of check names to run, e.g. [\"secrets\", \"rls\"]; omit to run all"),
    },
}, async ({ repoDir, siteUrl, checks: checkNames }) => {
    const ctx = loadContext({ repoDir, siteUrl });
    const enabled = loadEnabledChecks(checkNames);
    const results = await runChecks(ctx, enabled);
    return {
        content: [{ type: "text", text: renderMarkdown(results) }],
    };
});
for (const check of checks) {
    server.registerTool(`check_${check.name}`, {
        description: check.description,
        inputSchema: {
            repoDir: z.string().optional().describe("path to the repo to scan"),
            siteUrl: z.string().optional().describe("deployed site URL to probe"),
        },
    }, async ({ repoDir, siteUrl }) => {
        const ctx = loadContext({ repoDir, siteUrl });
        const results = await runChecks(ctx, [check]);
        return {
            content: [{ type: "text", text: renderMarkdown(results) }],
        };
    });
}
async function main() {
    const transport = new StdioServerTransport();
    await server.connect(transport);
}
main().catch((err) => {
    console.error(err instanceof Error ? err.stack ?? err.message : String(err));
    process.exit(1);
});
