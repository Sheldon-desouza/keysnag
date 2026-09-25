// The check registry. Each check lives at src/checks/<name>.ts and default-exports a Check.
import type { Check } from "../types.js";
import secrets from "./secrets.js";
import urlprobe from "./urlprobe.js";
import rls from "./rls.js";
import twoaccount from "./twoaccount.js";

export const checks: Check[] = [secrets, urlprobe, rls, twoaccount];
