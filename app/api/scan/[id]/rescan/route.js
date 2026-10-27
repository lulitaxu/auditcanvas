import { getScan, createScan, checkScanAllowed, scanSummary } from '../../../../../src/lib/scanstore.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

// POST /api/scan/[id]/rescan — start a fresh scan of the SAME target
// under the SAME policy as a completed scan (SPEC.md: scan diff + fix
// verification). The rescan is a new session linked to its predecessor
// (rescanOf); the client drives it through the normal step loop, and
// GET /api/scan/[newId]/diff compares the two finalized reports.
// Abuse controls are the same as for a fresh scan (cooldown + quota);
// demo hosts stay exempt from the cooldown so Judge mode is re-runnable.
export async function POST(request, { params }) {
  const { id } = await params;
  const original = getScan(id);
  if (!original) return Response.json({ error: 'Unknown scan ID.' }, { status: 404 });
  if (original.status !== 'complete') {
    return Response.json({ error: 'Only a completed scan can be rescanned.' }, { status: 409 });
  }

  const ip =
    request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    request.headers.get('x-real-ip') ||
    'local';

  const allowed = checkScanAllowed(original.target, ip);
  if (!allowed.ok) return Response.json({ error: allowed.reason }, { status: allowed.status });

  try {
    const session = createScan({
      url: original.target,
      attested: original.attested,
      ip,
      rescanOf: original.id,
    });
    return Response.json(scanSummary(session));
  } catch (err) {
    return Response.json(
      { error: `Rescan rejected: ${err && err.message ? err.message : String(err)}` },
      { status: 400 }
    );
  }
}
