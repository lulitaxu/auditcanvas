import { assertUrlAllowed } from '../../../../src/lib/safefetch.js';
import { createScanContext } from '../../../../src/lib/context.js';
import { deriveScanPolicy, checkStepAllowed } from '../../../../src/lib/scanstore.js';
import { groupById, runGroup } from '../../../../src/lib/scanner/index.js';
import { signStepBundle } from '../../../../src/lib/bundlesig.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const maxDuration = 60;

// POST /api/scan/step { scanId, target, attested, group }
// Runs exactly ONE check group in a fresh scan context and returns the
// group's results + the evidence it produced, HMAC-signed (see
// bundlesig.js). Stateless: the scan's policy is re-derived
// server-side from the target on every call (the client's
// scanId/attested carry no authority), so steps work across
// serverless instances and a step can be retried safely. The client
// carries the signed bundles to /api/scan/finalize, which verifies
// every signature and re-validates everything before a report exists
// (scanstore.assembleSession).
export async function POST(request) {
  let body;
  try {
    body = await request.json();
  } catch {
    return Response.json({ error: 'Request body must be JSON.' }, { status: 400 });
  }
  const group = groupById(body.group);
  if (!group) return Response.json({ error: `Unknown check group: ${body.group}` }, { status: 400 });

  const ip =
    request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    request.headers.get('x-real-ip') ||
    'local';
  const metered = checkStepAllowed(ip);
  if (!metered.ok) return Response.json({ error: metered.reason }, { status: metered.status });

  let parsed;
  try {
    parsed = assertUrlAllowed(typeof body.target === 'string' ? body.target.trim() : '');
  } catch (err) {
    return Response.json(
      { error: `Target rejected: ${err && err.message ? err.message : String(err)}` },
      { status: 400 }
    );
  }
  const selfOrigin = new URL(request.url).origin;
  const { policy, authorizationState, allowPrivate } = deriveScanPolicy(parsed, {
    attested: body.attested === true,
    selfOrigin,
  });
  const ctx = createScanContext({
    baseUrl: parsed.toString(),
    policy,
    authorizationState,
    allowPrivate,
  });

  const results = await runGroup(ctx, group.id);
  const bundle = {
    group: group.id,
    scanPolicy: policy.name,
    results,
    evidence: ctx.evidence.items,
    requests: ctx.requests,
  };
  // Provenance (security fix H1): sign the bundle against the scan
  // identity the client presented and the canonical target the server
  // validated. /finalize verifies this signature before trusting any
  // of the bundle's contents; an unsigned or edited bundle is
  // rejected there. The signature binds results to THIS scan — a
  // bundle transplanted into another scan does not verify.
  bundle.sig = signStepBundle({
    scanId: typeof body.scanId === 'string' ? body.scanId : '',
    target: parsed.toString(),
    bundle,
  });
  return Response.json(bundle);
}
