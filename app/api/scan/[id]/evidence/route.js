import { getScan } from '../../../../../src/lib/scanstore.js';
import { finalizeReport } from '../../../../../src/lib/pipeline.js';
import { buildEvidenceBundle, EVIDENCE_FILENAME } from '../../../../../src/lib/downloads.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

// GET /api/scan/[id]/evidence — auditcanvas-evidence.json: the redacted
// evidence bundle exactly as stored, with the versioned schema field.
// Every finding ID in it resolves to evidence IDs inside the same file.
export async function GET(request, { params }) {
  const { id } = await params;
  const session = getScan(id);
  if (!session) return Response.json({ error: 'Unknown scan ID.' }, { status: 404 });
  const report = await finalizeReport(session);
  const bundle = buildEvidenceBundle(report);
  return new Response(JSON.stringify(bundle, null, 2), {
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'content-disposition': `attachment; filename="${EVIDENCE_FILENAME}"`,
      'x-robots-tag': 'noindex, nofollow',
    },
  });
}
