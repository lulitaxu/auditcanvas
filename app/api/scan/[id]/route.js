import { getScan } from '../../../../src/lib/scanstore.js';
import { finalizeReport } from '../../../../src/lib/pipeline.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const maxDuration = 60;

// GET /api/scan/[id] — the finalized report: deterministic bundle +
// scores + reproducibility stamp, with chains validated/classified and
// refutation outcomes folded into the scoring (pipeline.js). When the
// auditor is not configured, the report carries the explicit
// engine-only status; it never pretends the model ran.
export async function GET(request, { params }) {
  const { id } = await params;
  const session = getScan(id);
  if (!session) return Response.json({ error: 'Unknown scan ID.' }, { status: 404 });
  const report = await finalizeReport(session);
  return Response.json(report);
}
