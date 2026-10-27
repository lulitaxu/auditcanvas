import { createChallenge, normalizeHostname } from '../../../../src/lib/ownership.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

// POST /api/verify/start { url } — issue a DNS TXT ownership challenge.
// The token is bound to the exact hostname and short-lived (15 min).
// The user publishes:  TXT  _auditcanvas.<host>  "auditcanvas-verify=…"
// then calls /api/verify/check. One method only, per spec.
export async function POST(request) {
  let body;
  try {
    body = await request.json();
  } catch {
    return Response.json({ error: 'Request body must be JSON.' }, { status: 400 });
  }
  const hostname = normalizeHostname(body.url || body.hostname || '');
  if (!hostname) return Response.json({ error: 'A valid target URL or hostname is required.' }, { status: 400 });
  const challenge = createChallenge(hostname);
  return Response.json({
    hostname: challenge.hostname,
    recordName: challenge.recordName,
    recordValue: challenge.recordValue,
    recordType: 'TXT',
    expiresAt: challenge.expiresAt,
    instructions: `Add a TXT record at ${challenge.recordName} with the exact value ${challenge.recordValue}, wait for DNS to propagate, then check the challenge. The token is valid only for ${challenge.hostname} and expires at ${challenge.expiresAt}.`,
  });
}
