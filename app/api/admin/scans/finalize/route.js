import { requireAdminApi } from '../../../../../src/lib/admin/guard.js';
import { finalizeAdminScan } from '../../../../../src/lib/admin/scans.js';
import { adminJson } from '../../../../../src/lib/admin/http.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const maxDuration = 60;

// POST /api/admin/scans/finalize { scan: { scanId }, bundles }
//
// Verifies the signed bundles through assembly WITH the admin grant
// (admin design §13.6), runs the pipeline, and PERSISTS the report
// in Neon before returning it: an admin report that cannot be stored
// is not delivered as authoritative. Repeat finalize of the same
// bundle set returns the stored report; a different set is a 409.
export async function POST(request) {
  const auth = await requireAdminApi(request, { csrf: true, routeClass: 'scan-finalize' });
  if (!auth.ok) return auth.response;
  const outcome = await finalizeAdminScan(request, { db: auth.db, cfg: auth.cfg, session: auth.session });
  return adminJson(outcome.json, outcome.status);
}
