import { buildFixPack, resolveDownloadReport, FIX_PACK_FILENAME } from '../../../../src/lib/downloads.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const maxDuration = 30;

// POST /api/scan/fix-pack { report, scan?, bundles? } —
// auditcanvas-fix-pack.zip, built statelessly (same report resolution
// as the evidence download: verified signed chain when carried, else
// the recomputed/unverified bare-report path — security fix M4). One
// suggested patch per finding, each headed with its finding ID,
// evidence IDs, stack, conditions, and placement; labelled a
// suggested patch, untested until a rescan verifies the fix.
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
