import { createScan, checkScanAllowed, scanSummary } from '../../../../src/lib/scanstore.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

// POST /api/scan/start { url, attested }
// Creates a scan session. Policy is decided server-side: only configured
// demo hosts get the full policy; every other target gets the restricted
// passive policy no matter what the client claims (SPEC.md).
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

  const allowed = checkScanAllowed(url, ip);
  if (!allowed.ok) return Response.json({ error: allowed.reason }, { status: allowed.status });

  try {
    const session = createScan({ url, attested: body.attested === true, ip });
    return Response.json(scanSummary(session));
  } catch (err) {
    return Response.json(
      { error: `Target rejected: ${err && err.message ? err.message : String(err)}` },
      { status: 400 }
    );
  }
}
