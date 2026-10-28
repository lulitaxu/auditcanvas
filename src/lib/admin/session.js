// Admin sessions (admin design §9, §10): server-issued random
// tokens, stored ONLY as SHA-256 hashes in Neon; the raw token lives
// in exactly one place — the browser's HttpOnly cookie. Login always
// rotates (all prior sessions revoked, fresh token minted after
// password verification), logout revokes, and every validation
// re-reads the durable row: there is no in-memory session fallback.
import { createHash, createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { isProduction } from './http.js';
import { toIso } from './db.js';

export const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12h, absolute
const LAST_SEEN_TOUCH_MS = 5 * 60 * 1000;
const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/; // 32 random bytes, base64url

export function sessionCookieName() {
  // Production uses the __Host- prefixed Secure cookie. Plain-HTTP
  // local development cannot set a __Host- Secure cookie, so dev uses
  // a clearly separate name; production never falls back to it.
  return isProduction() ? '__Host-ac_admin_session' : 'ac_admin_session';
}

export function generateSessionToken() {
  return randomBytes(32).toString('base64url');
}

export function hashSessionToken(rawToken) {
  return createHash('sha256').update(`auditcanvas-admin-session:v1:${rawToken}`).digest('hex');
}

export function serializeSessionCookie(rawToken) {
  const name = sessionCookieName();
  const attrs = [`${name}=${rawToken}`, 'Path=/', 'HttpOnly', 'SameSite=Lax', `Max-Age=${SESSION_TTL_MS / 1000}`];
  if (isProduction()) attrs.splice(2, 0, 'Secure');
  return attrs.join('; ');
}

export function serializeClearedSessionCookie() {
  const name = sessionCookieName();
  const attrs = [`${name}=`, 'Path=/', 'HttpOnly', 'SameSite=Lax', 'Max-Age=0'];
  if (isProduction()) attrs.splice(2, 0, 'Secure');
  return attrs.join('; ');
}

// Extract our session cookie's raw value from a request's Cookie
// header. Only the exact name for the current mode is honored; a
// value under any other name (including the dev name in production)
// is not a session.
export function rawSessionTokenFromRequest(request) {
  const header = request.headers.get('cookie');
  if (!header) return null;
  return rawSessionTokenFromCookieHeader(header);
}

export function rawSessionTokenFromCookieHeader(header) {
  if (typeof header !== 'string' || !header) return null;
  const name = sessionCookieName();
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() !== name) continue;
    const value = part.slice(eq + 1).trim();
    return value || null;
  }
  return null;
}

const SESSION_COLUMNS =
  'id, token_hash, created_at, last_seen_at, expires_at, revoked_at, created_ip_hash, browser_family, os_family';

export function normalizeSessionRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    tokenHash: row.token_hash,
    createdAt: toIso(row.created_at),
    lastSeenAt: toIso(row.last_seen_at),
    expiresAt: toIso(row.expires_at),
    revokedAt: toIso(row.revoked_at),
    createdIpHash: row.created_ip_hash || null,
    browserFamily: row.browser_family || null,
    osFamily: row.os_family || null,
  };
}

export function insertSessionStmt({ id, tokenHash, nowIso, expiresIso, ipHash, browserFamily, osFamily }) {
  return {
    text: `/*ac:sessions.insert*/ insert into public.admin_sessions
      (id, token_hash, created_at, last_seen_at, expires_at, created_ip_hash, browser_family, os_family)
      values ($1, $2, $3, $3, $4, $5, $6, $7)`,
    params: [id, tokenHash, nowIso, expiresIso, ipHash, browserFamily, osFamily],
  };
}

export function revokeAllSessionsStmt(nowIso) {
  return {
    text: `/*ac:sessions.revokeAll*/ update public.admin_sessions set revoked_at = $1 where revoked_at is null`,
    params: [nowIso],
  };
}

export function revokeSessionStmt(sessionId, nowIso) {
  return {
    text: `/*ac:sessions.revokeOne*/ update public.admin_sessions set revoked_at = $2
      where id = $1 and revoked_at is null`,
    params: [sessionId, nowIso],
  };
}

// Mint a brand-new session identity (id + raw token + row values).
// Pure: the caller persists it, inside the login transaction.
export function newSessionIdentity({ now, ipHash = null, browserFamily = null, osFamily = null }) {
  const rawToken = generateSessionToken();
  const session = {
    id: randomUUID(),
    tokenHash: hashSessionToken(rawToken),
    createdAt: new Date(now).toISOString(),
    lastSeenAt: new Date(now).toISOString(),
    expiresAt: new Date(now + SESSION_TTL_MS).toISOString(),
    revokedAt: null,
    createdIpHash: ipHash,
    browserFamily,
    osFamily,
  };
  return { rawToken, session };
}

// Validate a raw token against the durable store. Returns the
// normalized session, or null for unknown / revoked / expired —
// indistinguishably. Storage errors propagate as typed store errors
// (callers fail closed with 503); a session is NEVER fabricated in
// memory when Neon is unavailable.
export async function validateSessionToken(db, rawToken, { now = Date.now() } = {}) {
  if (typeof rawToken !== 'string' || !TOKEN_RE.test(rawToken)) return null;
  const tokenHash = hashSessionToken(rawToken);
  const rows = await db.query(
    `/*ac:sessions.byToken*/ select ${SESSION_COLUMNS} from public.admin_sessions where token_hash = $1`,
    [tokenHash]
  );
  if (!rows.length) return null;
  const session = normalizeSessionRow(rows[0]);
  if (session.revokedAt) return null;
  if (!(Date.parse(session.expiresAt) > now)) return null;
  // last_seen_at is observability only; it never extends expires_at.
  // Touch at most once per five minutes to avoid a write per call.
  if (now - Date.parse(session.lastSeenAt) >= LAST_SEEN_TOUCH_MS) {
    await db.query(
      `/*ac:sessions.touch*/ update public.admin_sessions set last_seen_at = $2 where id = $1`,
      [session.id, new Date(now).toISOString()]
    );
    session.lastSeenAt = new Date(now).toISOString();
  }
  return session;
}

export async function validateSessionRequest(db, request, opts = {}) {
  const raw = rawSessionTokenFromRequest(request);
  if (!raw) return null;
  return validateSessionToken(db, raw, opts);
}

// ---------------------------------------------------------------------------
// CSRF (design §10): a per-session token, derived — never stored —
// as base64url(HMAC-SHA256(ADMIN_CSRF_SECRET,
//   "auditcanvas-admin-csrf:v1:" + session.id + ":" + session.token_hash)).
// It rotates with the session, is bound to one session row and one
// token hash, and cannot be used as a cookie.
// ---------------------------------------------------------------------------

export function deriveCsrfToken(csrfSecret, session) {
  return createHmac('sha256', csrfSecret)
    .update(`auditcanvas-admin-csrf:v1:${session.id}:${session.tokenHash}`)
    .digest('base64url');
}

export function validateCsrfToken(csrfSecret, session, presented) {
  if (typeof presented !== 'string' || !presented) return false;
  const expected = deriveCsrfToken(csrfSecret, session);
  const a = Buffer.from(presented);
  const b = Buffer.from(expected);
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}
