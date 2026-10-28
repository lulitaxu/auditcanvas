import { requireAdminApi } from '../../../../../../src/lib/admin/guard.js';
import { getAdminRun } from '../../../../../../src/lib/admin/scans.js';
import { buildEvidenceBundle, EVIDENCE_FILENAME } from '../../../../../../src/lib/downloads.js';
import { insertAdminEvent } from '../../../../../../src/lib/admin/events.js';
import { adminHeaders, adminJson } from '../../../../../../src/lib/admin/http.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

// GET /api/admin/scans/[scanId]/evidence
//
// auditcanvas-evidence.json built from the STORED admin report only
// (admin design §13.8). There is no bare-report path here and no
// client-supplied report is accepted: a run that is absent, not an
// admin run, or not finalized is one generic 404, and a storage
// failure is a 503 — never a substitute artifact.
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
      metadata: { kind: 'evidence' },
    });
  } catch { /* telemetry never blocks the operator's own download */ }

  const bundle = buildEvidenceBundle(run.report);
  return new Response(JSON.stringify(bundle, null, 2), {
    headers: adminHeaders({
      'content-type': 'application/json; charset=utf-8',
      'content-disposition': `attachment; filename="${EVIDENCE_FILENAME}"`,
    }),
  });
}
