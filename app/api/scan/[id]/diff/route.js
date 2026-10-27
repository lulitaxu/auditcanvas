import { getScan } from '../../../../../src/lib/scanstore.js';
import { finalizeReport } from '../../../../../src/lib/pipeline.js';
import { diffReports } from '../../../../../src/lib/diff.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

// GET /api/scan/[id]/diff — the diff of THIS scan against the scan it
// rescanned (its rescanOf predecessor): resolved / new / persistent /
// severity-changed / could-not-repeat findings by stable check
// identity, plus the deterministic score movement (src/lib/diff.js).
// Findings a rescan could not re-verify are never reported as resolved.
export async function GET(request, { params }) {
  const { id } = await params;
  const session = getScan(id);
  if (!session) return Response.json({ error: 'Unknown scan ID.' }, { status: 404 });
  if (!session.rescanOf) {
    return Response.json({ error: 'This scan is not a rescan; there is no previous report to diff against.' }, { status: 400 });
  }
  const previous = getScan(session.rescanOf);
  if (!previous) return Response.json({ error: 'The previous scan is no longer available.' }, { status: 404 });
  if (session.status !== 'complete' || previous.status !== 'complete') {
    return Response.json({ error: 'Both scans must be complete before they can be diffed.' }, { status: 409 });
  }
  const before = await finalizeReport(previous);
  const after = await finalizeReport(session);
  return Response.json(diffReports(before, after));
}
