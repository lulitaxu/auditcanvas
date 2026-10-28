import { requireAdminApi } from '../../../../../src/lib/admin/guard.js';
import { startAdminScan } from '../../../../../src/lib/admin/scans.js';
import { adminJson } from '../../../../../src/lib/admin/http.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const maxDuration = 30;

// POST /api/admin/scans/start { url, rescanOf? }
//
// Creates ONE durable full-policy scan grant (admin design §13.4)
// and returns its descriptor. The grant — a Neon row bound to this
// session and the canonical target, expiring in 30 minutes — is the
// only thing that can authorize admin steps/finalize. No body field
// (admin, origin, policy, ...) confers anything; the public scan
// routes are a separate surface and never read the admin cookie.
export async function POST(request) {
  const auth = await requireAdminApi(request, { csrf: true, routeClass: 'scan-start' });
  if (!auth.ok) return auth.response;
  const outcome = await startAdminScan(request, { db: auth.db, cfg: auth.cfg, session: auth.session });
  return adminJson(outcome.json, outcome.status);
}
