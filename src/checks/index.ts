// The check registry. Each check lives at src/checks/<name>.ts and default-exports a Check.
// Order: static/offline checks first, then checks that hit the network or a database.
import type { Check } from "../types.js";
import secrets from "./secrets.js";
import config from "./config.js";
import authz from "./authz.js";
import injection from "./injection.js";
import payments from "./payments.js";
import backdoor from "./backdoor.js";
import aiEndpoints from "./ai-endpoints.js";
import deps from "./deps.js";
import storage from "./storage.js";
import leaks from "./leaks.js";
import urlprobe from "./urlprobe.js";
import rls from "./rls.js";
import twoaccount from "./twoaccount.js";

export const checks: Check[] = [
  secrets,
  config,
  authz,
  injection,
  payments,
  backdoor,
  aiEndpoints,
  deps,
  storage,
  leaks,
  urlprobe,
  rls,
  twoaccount,
];
