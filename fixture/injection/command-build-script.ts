// Non-derived command interpolation in a build script: baseRef comes from
// process.argv, not from an incoming request. Expected finding:
// injection.command (medium, not derived from a request).
import { execSync } from "node:child_process";

const baseRef = process.argv[2] ?? "main";
const changed = execSync(`git diff --name-only ${baseRef}..HEAD`).toString();
console.log(changed);
