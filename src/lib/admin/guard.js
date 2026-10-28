// Shared authentication guard for /api/admin/* handlers (admin
// design §2.3, §9.4, §10.3).
//
// Every admin API call validates, in order:
//   1. the configuration gate (not configured -> generic 503);
//   2. storage reachability (Neon down -> generic 503, fail closed);
//   3. the server-side session (missing/unknown/revoked/expired are
//      ONE indistinguishable generic 401 — never a policy downgrade,
//      never a hint about which check failed);
//   4. for state-changing calls, the per-session CSRF token plus the
//      same-origin check (failure -> generic 403 + a csrf_rejected
//      audit event; the response never says which part failed).
import { adminConfig } from './config.js';
import { getAdminDb, AdminStoreUnavailable } from './db.js';
import { adminJson, adminSourceHash, checkSameOrigin, clientIp } from './http.js';
import { validateSessionRequest, deriveCsrfToken, validateCsrfToken } from './session.js';
import { insertAdminEvent } from './events.js';

export async function requireAdminApi(request, { csrf = true, routeClass = 'admin', now = Date.now() } = {}) {
  const cfg = adminConfig();
  if (!cfg.configured) {
    return { ok: false, response: adminJson({ error: 'Admin is not configured.' }, 503) };
  }
  let db;
  try {
    db = getAdminDb();
  } catch {
    return { ok: false, response: adminJson({ error: 'Admin storage unavailable.' }, 503) };
  }

  let session = null;
  try {
    session = await validateSessionRequest(db, request, { now });
  } catch (err) {
    if (err instanceof AdminStoreUnavailable || (err && err.code === 'store_unavailable')) {
      return { ok: false, response: adminJson({ error: 'Admin storage unavailable.' }, 503) };
    }
    throw err;
  }
  if (!session) {
    return { ok: false, response: adminJson({ error: 'Admin authentication required.' }, 401) };
  }

  const csrfToken = deriveCsrfToken(cfg.csrfSecret, session);
  if (csrf) {
    const originOk = checkSameOrigin(request);
    const tokenOk = validateCsrfToken(cfg.csrfSecret, session, request.headers.get('x-ac-csrf'));
    if (!originOk || !tokenOk) {
      // Record the rejection with allowlisted metadata only. A
      // failure to record must not change the rejection itself.
      try {
        await insertAdminEvent(db, {
          type: 'csrf_rejected',
          occurredAt: new Date(now).toISOString(),
          actorSessionId: session.id,
          ipHash: adminSourceHash(cfg.visitorHashSecret, clientIp(request)),
          metadata: { route: routeClass },
        });
      } catch { /* the 403 stands */ }
      return { ok: false, response: adminJson({ error: 'Request rejected.' }, 403) };
    }
  }

  return { ok: true, cfg, db, session, csrfToken };
}
