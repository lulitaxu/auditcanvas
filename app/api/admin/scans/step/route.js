import { requireAdminApi } from '../../../../../src/lib/admin/guard.js';
import { runAdminStep } from '../../../../../src/lib/admin/scans.js';
import { adminJson } from '../../../../../src/lib/admin/http.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const maxDuration = 60;

// POST /api/admin/scans/step { scanId, target, group }
//
// Runs exactly ONE check group for a live admin grant (admin design
// §13.5) and returns the HMAC-signed bundle, like the public step
// route — but the grant is re-loaded and re-bound (creating session,
// canonical target, live status, expiry) on every call, and the
// step's completion is recorded durably before the bundle counts.
export async function POST(request) {
  const auth = await requireAdminApi(request, { csrf: true, routeClass: 'scan-step' });
  if (!auth.ok) return auth.response;
  const outcome = await runAdminStep(request, { db: auth.db, cfg: auth.cfg, session: auth.session });
  return adminJson(outcome.json, outcome.status);
}
