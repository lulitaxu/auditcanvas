import { requireAdminApi } from '../../../../../../src/lib/admin/guard.js';
import { getAdminRun } from '../../../../../../src/lib/admin/scans.js';
import { buildFixPack, FIX_PACK_FILENAME } from '../../../../../../src/lib/downloads.js';
import { insertAdminEvent } from '../../../../../../src/lib/admin/events.js';
import { adminHeaders, adminJson } from '../../../../../../src/lib/admin/http.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

// GET /api/admin/scans/[scanId]/fix-pack
//
// auditcanvas-fix-pack.zip built from the STORED admin report only
// (admin design §13.8). Same contract as the evidence route: generic
// 404 for absent/non-admin/non-finalized runs, 503 on storage
// failure, never a client-supplied substitute.
export async function GET(request, { params }) {
  const auth = await requireAdminApi(request, { csrf: false });
  if (!auth.ok) return auth.response;
  const { scanId } = await params;

  let run;
  try {
    run = await getAdminRun(auth.db, scanId);
  } catch (err) {
    if (err && (err.code === 'store_unavailable' || err.code === 'store_error')) {
      return adminJson({ error: 'Admin storage unavailable.' }, 503);
    }
    throw err;
  }
  if (!run || run.origin !== 'admin' || run.storedStatus !== 'finalized' || !run.report) {
    return adminJson({ error: 'Admin scan not found.' }, 404);
  }

  try {
    await insertAdminEvent(auth.db, {
      type: 'report_downloaded',
      occurredAt: new Date().toISOString(),
      actorSessionId: auth.session.id,
      scanId: run.scanId,
      targetHost: run.targetHost,
      metadata: { kind: 'fix-pack' },
    });
  } catch { /* telemetry never blocks the operator's own download */ }

  const zip = buildFixPack(run.report);
  return new Response(zip, {
    headers: adminHeaders({
      'content-type': 'application/zip',
      'content-disposition': `attachment; filename="${FIX_PACK_FILENAME}"`,
    }),
  });
}
