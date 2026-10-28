import { buildEvidenceBundle, resolveDownloadReport, EVIDENCE_FILENAME } from '../../../../src/lib/downloads.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const maxDuration = 30;

// POST /api/scan/evidence { report, scan?, bundles? } —
// auditcanvas-evidence.json, built statelessly. When the request
// carries the scan descriptor + the HMAC-signed step bundles, the
// report is assembled and finalized server-side from the verified
// chain (security fixes H1/M4) and the bundle is exactly what the
// ID-keyed GET route serves from a cached session. A bare report is
// never trusted: scores are recomputed, the stamp is re-derived, and
// integrity is labelled client-supplied-unverified (never ok:true).
export async function POST(request) {
  let body;
  try {
    body = await request.json();
  } catch {
    return Response.json({ error: 'Request body must be JSON.' }, { status: 400 });
  }
  const ip =
    request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    request.headers.get('x-real-ip') ||
    'local';
  const selfOrigin = new URL(request.url).origin;
  try {
    const report = await resolveDownloadReport(body, { ip, selfOrigin });
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
