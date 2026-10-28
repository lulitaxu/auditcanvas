import { requireAdminApi } from '../../../../src/lib/admin/guard.js';
import { logoutSession } from '../../../../src/lib/admin/auth.js';
import { adminJson } from '../../../../src/lib/admin/http.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

// POST /api/admin/logout — requires a valid session AND its CSRF
// token. Revokes the session row, records the event, clears the
// cookie. Replaying the old cookie afterwards is an unknown token.
export async function POST(request) {
  const auth = await requireAdminApi(request, { csrf: true, routeClass: 'logout' });
  if (!auth.ok) return auth.response;
  try {
    const outcome = await logoutSession(request, { db: auth.db, cfg: auth.cfg, session: auth.session });
    return adminJson(outcome.json, outcome.status, { 'Set-Cookie': outcome.setCookie });
  } catch (err) {
    if (err && err.code === 'store_unavailable') {
      return adminJson({ error: 'Admin storage unavailable.' }, 503);
    }
    throw err;
  }
}
