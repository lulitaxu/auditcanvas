// Server-page session resolution for /admin pages (admin design
// §9.4). Pages are server components: they read the session cookie
// through next/headers and validate it against the durable store on
// every render. Three outcomes, deliberately distinct:
//   - 'ok'   : a live session (carries the session + derived CSRF
//              token for the page's client components);
//   - 'anon' : no/invalid/expired/revoked session -> redirect to
//              /admin/login (the states are indistinguishable);
//   - 'down' : admin not configured or storage unreachable -> the
//              page renders its generic unavailable state (503
//              semantics), never a fabricated session.
import { cookies } from 'next/headers';
import { adminConfig } from './config.js';
import { getAdminDb } from './db.js';
import {
  sessionCookieName,
  validateSessionToken,
  deriveCsrfToken,
} from './session.js';

export async function resolveAdminPageSession() {
  const cfg = adminConfig();
  if (!cfg.configured) return { kind: 'down', reason: 'not-configured' };
  let db;
  try {
    db = getAdminDb();
  } catch {
    return { kind: 'down', reason: 'storage' };
  }
  let raw = null;
  try {
    const store = await cookies();
    raw = store.get(sessionCookieName())?.value || null;
  } catch {
    raw = null;
  }
  if (!raw) return { kind: 'anon' };
  try {
    const session = await validateSessionToken(db, raw);
    if (!session) return { kind: 'anon' };
    return { kind: 'ok', cfg, db, session, csrfToken: deriveCsrfToken(cfg.csrfSecret, session) };
  } catch {
    return { kind: 'down', reason: 'storage' };
  }
}
