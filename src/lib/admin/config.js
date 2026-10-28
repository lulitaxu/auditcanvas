// Admin configuration gate (admin design §6).
//
// The panel is enabled only when every required production value is
// present and parses. Public pages and public scan routes never
// consult this module. When configuration is absent or invalid the
// admin surface is inert: the login page shows a generic "not
// configured" state, admin APIs answer a generic 503, and there is no
// default, development, or fixture password anywhere to fall back to.
//
// Env is read lazily on every call (never captured at module load),
// so configuration changes apply with a redeploy and tests can drive
// the gate by setting the environment before invoking a handler.
import { isAdminPasswordHashValid } from './password.js';

export const ADMIN_ENV_VARS = [
  'AUDITCANVAS_DATABASE_URL',
  'ADMIN_PASSWORD_HASH',
  'ADMIN_CSRF_SECRET',
  'VISITOR_HASH_SECRET',
  'BUNDLE_SIGNING_SECRET',
];

// HMAC/bearer secrets are generated as `openssl rand -hex 32`, i.e.
// 64 hex characters. The floor enforced here is a 32-character
// string; anything shorter is treated as a configuration error, not
// silently accepted as a weak secret.
const MIN_SECRET_LENGTH = 32;

function present(value) {
  return typeof value === 'string' && value.length > 0;
}

export function adminConfig(env = process.env) {
  const missing = [];

  const databaseUrl = env.AUDITCANVAS_DATABASE_URL;
  if (!present(databaseUrl)) missing.push('AUDITCANVAS_DATABASE_URL');

  const passwordHash = env.ADMIN_PASSWORD_HASH;
  if (!present(passwordHash) || !isAdminPasswordHashValid(passwordHash)) {
    // A malformed hash is a configuration error (fail closed as "not
    // configured"); the parser never falls back to string comparison.
    missing.push('ADMIN_PASSWORD_HASH');
  }

  const csrfSecret = env.ADMIN_CSRF_SECRET;
  if (!present(csrfSecret) || csrfSecret.length < MIN_SECRET_LENGTH) missing.push('ADMIN_CSRF_SECRET');

  const visitorHashSecret = env.VISITOR_HASH_SECRET;
  if (!present(visitorHashSecret) || visitorHashSecret.length < MIN_SECRET_LENGTH) {
    missing.push('VISITOR_HASH_SECRET');
  }

  // Admin scans must fail closed if bundle signing would use the
  // ephemeral per-process fallback (bundlesig.js): a grant can cross
  // serverless instances, an ephemeral secret cannot.
  const bundleSigningSecret = env.BUNDLE_SIGNING_SECRET;
  if (!present(bundleSigningSecret)) missing.push('BUNDLE_SIGNING_SECRET');

  return {
    configured: missing.length === 0,
    missing, // variable NAMES only — safe for server logs, never values
    databaseUrl: present(databaseUrl) ? databaseUrl : null,
    passwordHash: present(passwordHash) ? passwordHash : null,
    csrfSecret: present(csrfSecret) ? csrfSecret : null,
    visitorHashSecret: present(visitorHashSecret) ? visitorHashSecret : null,
  };
}
