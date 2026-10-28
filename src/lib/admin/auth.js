// Admin login/logout workflow (admin design §8, §9.5).
//
// The login sequence runs in the design's exact order: origin check
// before any password work; durable backoff from admin_events before
// scrypt (a rate-limited request never runs the password check, even
// if the password happens to be correct); scrypt + timingSafeEqual;
// and on success ONE transaction that records the success, revokes
// every prior session, and inserts the fresh session — no session
// exists before password verification completes.
import { adminSourceHash, checkSameOrigin, clientIp, readJsonBody, BodyError } from './http.js';
import { verifyAdminPassword } from './password.js';
import { parseUserAgent } from './ua.js';
import {
  insertAdminEvent,
  insertAdminEventStmt,
  lastLoginSuccessAt,
  loginFailureTimes,
} from './events.js';
import {
  newSessionIdentity,
  insertSessionStmt,
  revokeAllSessionsStmt,
  revokeSessionStmt,
  serializeSessionCookie,
  serializeClearedSessionCookie,
} from './session.js';

const FAILURE_WINDOW_MS = 60 * 60 * 1000; // per-source: last 60 minutes
const GLOBAL_WINDOW_MS = 15 * 60 * 1000; // breaker: 50 failures / 15 minutes
const GLOBAL_BREAKER_THRESHOLD = 50;
const GLOBAL_BREAKER_MS = 15 * 60 * 1000;

// design §8.3: delay before another password check, measured from
// the most recent failure.
export function backoffDelaySeconds(failures) {
  if (failures >= 10) return 900;
  if (failures >= 5) return Math.min(300, 5 * 2 ** (failures - 5));
  return 0;
}

const LOGIN_BODY_MAX = 4 * 1024;

function result(status, json, extra = {}) {
  return { status, json, ...extra };
}

// Returns a plain result descriptor; the route turns it into a
// Response. Assumes the configuration gate already passed (the route
// answers 503 before calling this when admin is not configured).
export async function loginWithPassword(request, { db, cfg, now = Date.now() }) {
  // Origin first: a cross-origin (or, in production, origin-less)
  // login POST is rejected before body parsing and before any
  // password work of any kind.
  if (!checkSameOrigin(request)) {
    return result(403, { error: 'Request rejected.' });
  }

  let body;
  try {
    body = await readJsonBody(request, LOGIN_BODY_MAX);
  } catch (err) {
    if (err instanceof BodyError) return result(err.status, { error: 'Invalid request.' });
    throw err;
  }
  // Only { password } is read; unexpected fields are ignored, never
  // echoed. A missing/non-string password flows through the failure
  // path like any other wrong password.
  const password = typeof body.password === 'string' ? body.password : '';

  const ip = clientIp(request);
  const ipHash = adminSourceHash(cfg.visitorHashSecret, ip);
  const ua = parseUserAgent(request.headers.get('user-agent'));
  const nowIso = new Date(now).toISOString();

  // Durable backoff state (design §8.3): consecutive failures in the
  // last 60 minutes since this source's most recent success.
  const lastSuccessIso = await lastLoginSuccessAt(db, ipHash);
  const windowStart = Math.max(now - FAILURE_WINDOW_MS, lastSuccessIso ? Date.parse(lastSuccessIso) : 0);
  const failureTimes = await loginFailureTimes(db, { ipHash, sinceIso: new Date(windowStart).toISOString() });
  const failures = failureTimes.length;
  const delaySec = backoffDelaySeconds(failures);
  let limitedUntil = 0;
  let scope = 'source';
  if (delaySec > 0 && failureTimes.length) {
    limitedUntil = Math.max(limitedUntil, Date.parse(failureTimes[0]) + delaySec * 1000);
  }
  // Global circuit breaker: 50+ failures across all sources in 15
  // minutes closes login for 15 minutes from the 50th failure. The
  // tradeoff (an attacker can briefly lock the sole operator out) is
  // explicit in the design and accepted.
  const globalTimes = await loginFailureTimes(db, {
    ipHash: null,
    sinceIso: new Date(now - GLOBAL_WINDOW_MS - GLOBAL_BREAKER_MS).toISOString(),
  });
  const inWindow = globalTimes.filter((t) => Date.parse(t) > now - GLOBAL_WINDOW_MS);
  if (inWindow.length >= GLOBAL_BREAKER_THRESHOLD) {
    const fiftieth = Date.parse(inWindow[GLOBAL_BREAKER_THRESHOLD - 1]);
    if (fiftieth + GLOBAL_BREAKER_MS > limitedUntil) {
      limitedUntil = fiftieth + GLOBAL_BREAKER_MS;
      scope = 'global';
    }
  }
  if (limitedUntil > now) {
    await insertAdminEvent(db, {
      type: 'login_rate_limited',
      occurredAt: nowIso,
      ipHash,
      browserFamily: ua.browserFamily,
      osFamily: ua.osFamily,
      metadata: { scope, failures },
    });
    return result(
      429,
      { error: 'Too many attempts. Try again later.' },
      { retryAfterSec: Math.ceil((limitedUntil - now) / 1000) }
    );
  }

  const ok = verifyAdminPassword(password, cfg.passwordHash);
  if (!ok) {
    await insertAdminEvent(db, {
      type: 'login_failure',
      occurredAt: nowIso,
      ipHash,
      browserFamily: ua.browserFamily,
      osFamily: ua.osFamily,
    });
    return result(401, { error: 'Invalid password.' });
  }

  // Success: one transaction — record, revoke all prior sessions,
  // mint the fresh session. Rotation is what makes fixation
  // impossible: any cookie value an attacker planted is ignored as
  // authority here and cannot become the new session.
  const { rawToken, session } = newSessionIdentity({
    now,
    ipHash,
    browserFamily: ua.browserFamily,
    osFamily: ua.osFamily,
  });
  // (Statement order inside the transaction puts the session row
  // before the event that references it as actor; the three writes
  // remain one atomic unit.)
  await db.tx([
    revokeAllSessionsStmt(nowIso),
    insertSessionStmt({
      id: session.id,
      tokenHash: session.tokenHash,
      nowIso,
      expiresIso: session.expiresAt,
      ipHash,
      browserFamily: ua.browserFamily,
      osFamily: ua.osFamily,
    }),
    insertAdminEventStmt({
      type: 'login_success',
      occurredAt: nowIso,
      actorSessionId: session.id,
      ipHash,
      browserFamily: ua.browserFamily,
      osFamily: ua.osFamily,
    }),
  ]);
  return result(200, { ok: true }, { setCookie: serializeSessionCookie(rawToken) });
}

// Logout (design §9.5): revoke the current session row and record
// the event in one transaction, then clear the cookie. Replaying the
// old cookie afterwards is an unknown token: generic 401, no state.
export async function logoutSession(request, { db, cfg, session, now = Date.now() }) {
  const ipHash = adminSourceHash(cfg.visitorHashSecret, clientIp(request));
  const nowIso = new Date(now).toISOString();
  await db.tx([
    revokeSessionStmt(session.id, nowIso),
    insertAdminEventStmt({
      type: 'logout',
      occurredAt: nowIso,
      actorSessionId: session.id,
      ipHash,
    }),
  ]);
  return result(200, { ok: true }, { setCookie: serializeClearedSessionCookie() });
}
