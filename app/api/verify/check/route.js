import { checkChallenge, normalizeHostname } from '../../../../../src/lib/ownership.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

// POST /api/verify/check { hostname } — look up the TXT challenge in
// DNS. On success the hostname is marked verified server-side, and
// scans created afterwards for that exact hostname run the full
// policy with their verification state stored on the session.
export async function POST(request) {
  let body;
  try {
    body = await request.json();
  } catch {
    return Response.json({ error: 'Request body must be JSON.' }, { status: 400 });
  }
  const hostname = normalizeHostname(body.hostname || body.url || '');
  if (!hostname) return Response.json({ error: 'A valid hostname is required.' }, { status: 400 });
  const result = await checkChallenge(hostname);
  const status = result.status === 'verified' ? 200 : 409;
  return Response.json(result, { status });
}
