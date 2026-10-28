import { buildFixPack, assertClientReport, FIX_PACK_FILENAME } from '../../../../src/lib/downloads.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const maxDuration = 30;

// POST /api/scan/fix-pack { report } — auditcanvas-fix-pack.zip,
// built statelessly from the finalized report the client holds (same
// validation as the evidence download). One suggested patch per
// finding, each headed with its finding ID, evidence IDs, stack,
// conditions, and placement; labelled a suggested patch, untested
// until a rescan verifies the fix.
export async function POST(request) {
  let body;
  try {
    body = await request.json();
  } catch {
    return Response.json({ error: 'Request body must be JSON.' }, { status: 400 });
  }
  try {
    const report = assertClientReport(body.report);
    const zip = buildFixPack(report);
    return new Response(zip, {
      headers: {
        'content-type': 'application/zip',
        'content-disposition': `attachment; filename="${FIX_PACK_FILENAME}"`,
        'x-robots-tag': 'noindex, nofollow',
      },
    });
  } catch (err) {
    return Response.json(
      { error: `Fix pack rejected: ${err && err.message ? err.message : String(err)}` },
      { status: 400 }
    );
  }
}
