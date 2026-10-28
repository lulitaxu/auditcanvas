import { checkScanAllowed, startScanDescriptor } from '../../../../src/lib/scanstore.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const maxDuration = 30;

// POST /api/scan/start { url, attested }
// Issues a stateless scan descriptor. Policy is decided server-side:
// the app's own seeded demo target (same origin, /api/demo-target),
// configured demo hosts, and DNS-verified hosts get the full policy;
// every other target gets the restricted passive policy no matter what
// the client claims (SPEC.md). No session is stored: on serverless the
// client carries the descriptor and the step bundles to /finalize.
export async function POST(request) {
  let body;
  try {
    body = await request.json();
  } catch {
    return Response.json({ error: 'Request body must be JSON.' }, { status: 400 });
  }
  const url = typeof body.url === 'string' ? body.url.trim() : '';
  if (!url) return Response.json({ error: 'A target URL is required.' }, { status: 400 });

  const ip =
    request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    request.headers.get('x-real-ip') ||
    'local';
  const selfOrigin = new URL(request.url).origin;

  const allowed = checkScanAllowed(url, ip, selfOrigin);
  if (!allowed.ok) return Response.json({ error: allowed.reason }, { status: allowed.status });

  try {
    const descriptor = startScanDescriptor({ url, attested: body.attested === true, ip, selfOrigin });
    return Response.json(descriptor);
  } catch (err) {
    return Response.json(
      { error: `Target rejected: ${err && err.message ? err.message : String(err)}` },
      { status: 400 }
    );
  }
}
