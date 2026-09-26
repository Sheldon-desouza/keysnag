// Fixture: a local env merge, never serialised or sent anywhere. Must produce zero
// findings from backdoor.env_dump.
declare function parseEnvFile(path: string): Record<string, string | undefined>;

export function loadEnv(p: string) {
  const env = { ...parseEnvFile(p), ...process.env };
  return env;
}
