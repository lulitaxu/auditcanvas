import { checkScanAllowed, startScanDescriptor } from '../../../../src/lib/scanstore.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const maxDuration = 30;

// POST /api/scan/rescan { target, attested, rescanOf }
// Stateless rescan: a fresh scan descriptor for the SAME target,
// linked to the scan it follows (SPEC.md: scan diff + fix
// verification). The client drives it through the normal step loop and
// posts the two finalized reports to /api/scan/diff. Same abuse
// controls as a fresh scan (cooldown + quota; demo hosts exempt).
export async function POST(request) {
  let body;
  try {
    body = await request.json();
  } catch {
    return Response.json({ error: 'Request body must be JSON.' }, { status: 400 });
  }
  const target = typeof body.target === 'string' ? body.target.trim() : '';
  const rescanOf = typeof body.rescanOf === 'string' ? body.rescanOf : '';
  if (!target || !rescanOf) {
    return Response.json({ error: 'A rescan needs the original target and scan ID.' }, { status: 400 });
  }

  const ip =
    request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    request.headers.get('x-real-ip') ||
    'local';
  const selfOrigin = new URL(request.url).origin;

  const allowed = checkScanAllowed(target, ip, selfOrigin);
  if (!allowed.ok) return Response.json({ error: allowed.reason }, { status: allowed.status });

  try {
    const descriptor = startScanDescriptor({
      url: target,
      attested: body.attested === true,
      ip,
      rescanOf,
      selfOrigin,
    });
    return Response.json(descriptor);
  } catch (err) {
    return Response.json(
      { error: `Rescan rejected: ${err && err.message ? err.message : String(err)}` },
      { status: 400 }
    );
  }
}
