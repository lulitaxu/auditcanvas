import { adminConfig } from '../../../../src/lib/admin/config.js';
import { getAdminDb } from '../../../../src/lib/admin/db.js';
import { adminJson, adminSourceHash, clientIp } from '../../../../src/lib/admin/http.js';
import { loginWithPassword } from '../../../../src/lib/admin/auth.js';
import { insertAdminEvent } from '../../../../src/lib/admin/events.js';
import { parseUserAgent } from '../../../../src/lib/admin/ua.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

// POST /api/admin/login { password }
//
// The ONLY unauthenticated admin API. It has no session yet, so CSRF
// defense is the strict same-origin check inside the login service;
// the password check itself is gated by durable exponential backoff
// and runs scrypt + timingSafeEqual. Every response is generic:
// "Invalid password." covers wrong passwords, and configuration or
// storage failures are indistinguishable 503s.
export async function POST(request) {
  const cfg = adminConfig();
  if (!cfg.configured) {
    // Record a configuration-error event if storage is reachable
    // (design §6) — names only in server logs, nothing in the reply.
    console.error(`[auditcanvas] admin login attempted while admin is not configured (missing: ${cfg.missing.join(', ')})`);
    if (cfg.databaseUrl && cfg.visitorHashSecret) {
      try {
        const ua = parseUserAgent(request.headers.get('user-agent'));
        await insertAdminEvent(getAdminDb(), {
          type: 'login_config_error',
          occurredAt: new Date().toISOString(),
          ipHash: adminSourceHash(cfg.visitorHashSecret, clientIp(request)),
          browserFamily: ua.browserFamily,
          osFamily: ua.osFamily,
        });
      } catch { /* the 503 stands */ }
    }
    return adminJson({ error: 'Admin is not configured.' }, 503);
  }

  let db;
  try {
    db = getAdminDb();
  } catch {
    return adminJson({ error: 'Admin storage unavailable.' }, 503);
  }

  try {
    const outcome = await loginWithPassword(request, { db, cfg });
    const headers = {};
    if (outcome.retryAfterSec) headers['Retry-After'] = String(outcome.retryAfterSec);
    if (outcome.setCookie) headers['Set-Cookie'] = outcome.setCookie;
    return adminJson(outcome.json, outcome.status, headers);
  } catch (err) {
    if (err && err.code === 'store_unavailable') {
      return adminJson({ error: 'Admin storage unavailable.' }, 503);
    }
    throw err;
  }
}
