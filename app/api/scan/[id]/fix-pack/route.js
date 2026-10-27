import { getScan } from '../../../../../src/lib/scanstore.js';
import { finalizeReport } from '../../../../../src/lib/pipeline.js';
import { buildFixPack, FIX_PACK_FILENAME } from '../../../../../src/lib/downloads.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

// GET /api/scan/[id]/fix-pack — auditcanvas-fix-pack.zip: one suggested
// patch per finding, each file headed with its finding ID, evidence
// IDs, stack, conditions, and placement. Labelled a suggested patch,
// untested until a rescan verifies the fix.
export async function GET(request, { params }) {
  const { id } = await params;
  const session = getScan(id);
  if (!session) return Response.json({ error: 'Unknown scan ID.' }, { status: 404 });
  const report = await finalizeReport(session);
  const zip = buildFixPack(report);
  return new Response(zip, {
    headers: {
      'content-type': 'application/zip',
      'content-disposition': `attachment; filename="${FIX_PACK_FILENAME}"`,
      'x-robots-tag': 'noindex, nofollow',
    },
  });
}
