import { buildEvidenceBundle, assertClientReport, EVIDENCE_FILENAME } from '../../../../src/lib/downloads.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const maxDuration = 30;

// POST /api/scan/evidence { report } — auditcanvas-evidence.json,
// built statelessly from the finalized report the client holds. The
// report passes the report validator (schema + reference resolution +
// recomputed integrity) before the bundle is built, and the bundle is
// exactly what the ID-keyed GET route serves from a cached session.
export async function POST(request) {
  let body;
  try {
    body = await request.json();
  } catch {
    return Response.json({ error: 'Request body must be JSON.' }, { status: 400 });
  }
  try {
    const report = assertClientReport(body.report);
    const bundle = buildEvidenceBundle(report);
    return new Response(JSON.stringify(bundle, null, 2), {
      headers: {
        'content-type': 'application/json; charset=utf-8',
        'content-disposition': `attachment; filename="${EVIDENCE_FILENAME}"`,
        'x-robots-tag': 'noindex, nofollow',
      },
    });
  } catch (err) {
    return Response.json(
      { error: `Evidence bundle rejected: ${err && err.message ? err.message : String(err)}` },
      { status: 400 }
    );
  }
}
