import { assembleSession, cacheSession, AssemblyError, checkFinalizeAllowed } from '../../../../src/lib/scanstore.js';
import { finalizeReportForBundleSet } from '../../../../src/lib/pipeline.js';
import { bundleSetDigest } from '../../../../src/lib/bundlesig.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const maxDuration = 60;

// POST /api/scan/finalize { scan: {scanId, target, attested, rescanOf,
// createdAt}, bundles: [{group, scanPolicy, results, evidence,
// requests, sig}] }
//
// The server-side assembly point of the stateless scan flow. The
// bundles the client carried are NOT trusted: every bundle must carry
// the /step route's HMAC signature, verified inside assembleSession
// against this scanId + canonical target before any contents are
// trusted (security fix H1 — unsigned, tampered, or transplanted
// bundles are rejected before any model call can happen).
// assembleSession then re-derives the policy from the target,
// schema-validates every result and evidence item, re-redacts
// evidence, dedupes and renumbers evidence server-side, and rejects
// any reference that does not resolve. Only then does the pipeline
// run (deterministic report, auditor pass, chain validation,
// refutation, rescoring).
//
// Abuse metering (security fix H2): this route is metered per IP
// like /start and /step, and finalized reports are cached by the
// verified bundle-set digest — a repeat finalize of identical
// bundles returns the cached report with ZERO new model calls, so
// the 3-model-call cap holds per bundle-set, not per invocation.
// The finalized session is cached best-effort for the ID-keyed
// download/diff routes.
export async function POST(request) {
  let body;
  try {
    body = await request.json();
  } catch {
    return Response.json({ error: 'Request body must be JSON.' }, { status: 400 });
  }
  const scan = body && typeof body.scan === 'object' ? body.scan : {};
  const ip =
    request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    request.headers.get('x-real-ip') ||
    'local';
  const selfOrigin = new URL(request.url).origin;

  const metered = checkFinalizeAllowed(ip);
  if (!metered.ok) return Response.json({ error: metered.reason }, { status: metered.status });

  try {
    const session = assembleSession({
      scanId: scan.scanId,
      target: typeof scan.target === 'string' ? scan.target : '',
      attested: scan.attested === true,
      rescanOf: typeof scan.rescanOf === 'string' ? scan.rescanOf : null,
      createdAt: typeof scan.createdAt === 'string' ? scan.createdAt : null,
      bundles: body.bundles,
      ip,
      selfOrigin,
    });
    const bundleSetKey = bundleSetDigest({ scanId: session.id, target: session.target, bundles: body.bundles });
    const { report, cacheHit } = await finalizeReportForBundleSet(session, bundleSetKey);
    cacheSession(session);
    return Response.json(report, {
      headers: { 'x-auditcanvas-finalize-cache': cacheHit ? 'hit' : 'miss' },
    });
  } catch (err) {
    const status = err instanceof AssemblyError ? err.status : 400;
    return Response.json(
      { error: `Finalize rejected: ${err && err.message ? err.message : String(err)}` },
      { status }
    );
  }
}
