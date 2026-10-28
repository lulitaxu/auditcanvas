import { assembleSession, cacheSession, AssemblyError } from '../../../../src/lib/scanstore.js';
import { finalizeReport } from '../../../../src/lib/pipeline.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const maxDuration = 60;

// POST /api/scan/finalize { scan: {scanId, target, attested, rescanOf,
// createdAt}, bundles: [{group, results, evidence, requests}] }
//
// The server-side assembly point of the stateless scan flow. The
// bundles the client carried are NOT trusted: assembleSession
// re-derives the policy from the target, schema-validates every
// result and evidence item, re-redacts evidence, dedupes and
// renumbers evidence server-side, and rejects any reference that does
// not resolve. Only then does the pipeline run (deterministic report,
// auditor pass, chain validation, refutation, rescoring — the
// 3-model-call cap lives in pipeline.js/auditor.js). The finalized
// session is cached best-effort for the ID-keyed download/diff routes.
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
    const report = await finalizeReport(session);
    cacheSession(session);
    return Response.json(report);
  } catch (err) {
    const status = err instanceof AssemblyError ? err.status : 400;
    return Response.json(
      { error: `Finalize rejected: ${err && err.message ? err.message : String(err)}` },
      { status }
    );
  }
}
