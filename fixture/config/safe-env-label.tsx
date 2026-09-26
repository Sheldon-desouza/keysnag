"use client";

// SAFE FIXTURE — an admin docs component that lists env var NAMES as UI label strings.
// It never reads or uses the service_role key, so it must NOT fire
// config.service_role_in_client (fix K: a bare name string is not use).
const ENV_VAR_REFERENCE = {
  keys: ["NEXT_PUBLIC_SUPABASE_URL", "NEXT_PUBLIC_SUPABASE_ANON_KEY", "SUPABASE_SERVICE_ROLE_KEY"],
};

export function EnvVarReferenceCard() {
  return (
    <ul>
      {ENV_VAR_REFERENCE.keys.map((k) => (
        <li key={k}>{k}</li>
      ))}
    </ul>
  );
}
